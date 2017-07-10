package daemon

import (
	"fmt"
	"strings"

	"github.com/Sirupsen/logrus"
	"github.com/containers/image/docker/daemon"
	ciReference "github.com/containers/image/docker/reference"
	ciImage "github.com/containers/image/image"
	"github.com/containers/image/signature"
	"github.com/containers/image/transports"
	"github.com/docker/docker/container"
	"github.com/docker/docker/errors"
	"github.com/docker/docker/image"
	"github.com/docker/docker/layer"
	"github.com/docker/docker/pkg/idtools"
	"github.com/docker/docker/pkg/stringid"
	"github.com/docker/docker/reference"
	"github.com/docker/docker/runconfig"
	volumestore "github.com/docker/docker/volume/store"
	"github.com/docker/engine-api/types"
	containertypes "github.com/docker/engine-api/types/container"
	networktypes "github.com/docker/engine-api/types/network"
	digest "github.com/opencontainers/go-digest"
	"github.com/opencontainers/runc/libcontainer/label"
)

// CreateManagedContainer creates a container that is managed by a Service
func (daemon *Daemon) CreateManagedContainer(params types.ContainerCreateConfig) (types.ContainerCreateResponse, error) {
	return daemon.containerCreate(params, true)
}

// ContainerCreate creates a regular container
func (daemon *Daemon) ContainerCreate(params types.ContainerCreateConfig) (types.ContainerCreateResponse, error) {
	return daemon.containerCreate(params, false)
}

func (daemon *Daemon) containerCreate(params types.ContainerCreateConfig, managed bool) (types.ContainerCreateResponse, error) {
	if params.Config == nil {
		return types.ContainerCreateResponse{}, fmt.Errorf("Config cannot be empty in order to create a container")
	}

	warnings, err := daemon.verifyContainerSettings(params.HostConfig, params.Config, false)
	if err != nil {
		return types.ContainerCreateResponse{Warnings: warnings}, err
	}

	err = daemon.verifyNetworkingConfig(params.NetworkingConfig)
	if err != nil {
		return types.ContainerCreateResponse{}, err
	}

	if params.HostConfig == nil {
		params.HostConfig = &containertypes.HostConfig{}
	}
	err = daemon.adaptContainerSettings(params.HostConfig, params.AdjustCPUShares)
	if err != nil {
		return types.ContainerCreateResponse{Warnings: warnings}, err
	}

	container, err := daemon.create(params, managed)
	if err != nil {
		return types.ContainerCreateResponse{Warnings: warnings}, daemon.imageNotExistToErrcode(err)
	}

	return types.ContainerCreateResponse{ID: container.ID, Warnings: warnings}, nil
}

// Create creates a new container from the given configuration with a given name.
func (daemon *Daemon) create(params types.ContainerCreateConfig, managed bool) (retC *container.Container, retErr error) {
	var (
		container *container.Container
		img       *image.Image
		imgID     image.ID
		err       error
	)

	if params.Config.Image != "" {
		img, err = daemon.GetImage(params.Config.Image)
		if err != nil {
			return nil, err
		}
		imgID = img.ID()
	}

	if err := isRunningImageAllowed(params.Config.Image, imgID); err != nil {
		return nil, err
	}

	if err := daemon.mergeAndVerifyConfig(params.Config, img); err != nil {
		return nil, err
	}

	if err := daemon.mergeAndVerifyLogConfig(&params.HostConfig.LogConfig); err != nil {
		return nil, err
	}

	if container, err = daemon.newContainer(params.Name, params.Config, imgID, managed); err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			if err := daemon.cleanupContainer(container, true); err != nil {
				logrus.Errorf("failed to cleanup container on create error: %v", err)
			}
		}
	}()

	if err := daemon.setSecurityOptions(container, params.HostConfig); err != nil {
		return nil, err
	}

	container.HostConfig.StorageOpt = params.HostConfig.StorageOpt

	// Set RWLayer for container after mount labels have been set
	if err := daemon.setRWLayer(container); err != nil {
		return nil, err
	}

	rootUID, rootGID, err := idtools.GetRootUIDGID(daemon.uidMaps, daemon.gidMaps)
	if err != nil {
		return nil, err
	}
	if err := idtools.MkdirAs(container.Root, 0700, rootUID, rootGID); err != nil {
		return nil, err
	}

	if err := daemon.setHostConfig(container, params.HostConfig); err != nil {
		return nil, err
	}
	defer func() {
		if retErr != nil {
			if err := daemon.removeMountPoints(container, true); err != nil {
				logrus.Error(err)
			}
		}
	}()

	if err := daemon.createContainerPlatformSpecificSettings(container, params.Config, params.HostConfig); err != nil {
		return nil, err
	}

	var endpointsConfigs map[string]*networktypes.EndpointSettings
	if params.NetworkingConfig != nil {
		endpointsConfigs = params.NetworkingConfig.EndpointsConfig
	}
	// Make sure NetworkMode has an acceptable value. We do this to ensure
	// backwards API compatibility.
	container.HostConfig = runconfig.SetDefaultNetModeIfBlank(container.HostConfig)

	if err := daemon.updateContainerNetworkSettings(container, endpointsConfigs); err != nil {
		return nil, err
	}

	if err := container.ToDisk(); err != nil {
		logrus.Errorf("Error saving new container to disk: %v", err)
		return nil, err
	}
	if err := daemon.Register(container); err != nil {
		return nil, err
	}
	daemon.LogContainerEvent(container, "create")
	return container, nil
}

var canonicalZeroBytesDigest = digest.Canonical.FromBytes([]byte{})

// isRunningImageAllowed verifies whether the containers/image/signature.Policy
// allows using image imgID with name refOrID.
// Both imgID and refOrID may be "" if a container is being created without basing it on an image.
func isRunningImageAllowed(refOrID string, imgID image.ID) error {
	// configDigest may be the digest of a config created by docker on import of a schema1
	// image; that’s fine, c/i/docker/daemon/extra will not find any data signatures, and
	// a signedBy policy requirement will necessarily fail.
	configDigest := digest.Digest(imgID)
	if configDigest == "" {
		// No parent image is used.  An empty byte array is not a valid config JSON,
		// so this should not match any real image.
		configDigest = canonicalZeroBytesDigest
	}

	if refOrID == "" {
		// No parent image is used.  Pretend that the user specified an imageID
		// corresponding to the nothing-matching configDigest selected above.
		refOrID = canonicalZeroBytesDigest.String()
	}
	// NOTE:
	// - This does not do reference.store.defaultRegistries expansion!
	// - The lokup of imgID via Daemon.GetImage{,ID} also parses refRef as
	//   $name:$imgIDPrefix, $imgIDPrefix, $algo:$imgIDPrefix.  We do nothing
	//   about these formats.
	//
	// In both cases, we pass the users’ input straight to ciReference.ParseNormalizedNamed
	// and pc.IsRunningImageAllowed; they either don’t care and accept everything,
	// or match this against a signature, and ordinarily fail (unless the policy
	// is intentionally flexible to allow them, using matchRepository and the like).
	//
	// That is, in the typical use, if signature verification is set up in the policy,
	// containers can only be started if they refeer to images using the
	// docker/distribution/reference-like name[:tag] and name@digest formats .
	refID, refRef, err := reference.ParseIDOrReference(refOrID)
	if err != nil {
		return fmt.Errorf("Error parsing image ID/reference %s for policy enforcement: %v", refOrID, err)
	}
	// Exactly one of the two return values should be set.  This is currently always true;
	// verify to protect against this changing, which would then cause daemon.NewReference
	// to fail in a more surprising way.
	if (refID != "") == (refRef != nil) {
		return fmt.Errorf("Internal error parsing image ID/reference %s for policy enforcement: neither or both ID %#v and reference %#v returned", refOrID, refID, refRef)
	}
	var ciRef ciReference.Named
	if refRef != nil {
		// we can't use upstream docker/docker/reference since in projectatomic/docker
		// we modified docker/docker/reference and it's not doing any normalization.
		// we instead forked docker/docker/reference in containers/image and we need
		// this parsing here to make sure signature naming checks are consistent.
		r, err := ciReference.ParseNormalizedNamed(refRef.String())
		if err != nil {
			return fmt.Errorf("Internal error processsing image name %s for policy enforcement: %v", refRef.String(), err)
		}
		ciRef = r
	}

	defaultPolicy, err := signature.DefaultPolicy(nil)
	if err != nil {
		return fmt.Errorf("Error parsing signature verification policy: %v", err)
	}
	policyContext, err := signature.NewPolicyContext(defaultPolicy)
	if err != nil {
		return fmt.Errorf("Error preparing to verify signatures: %v", err)
	}
	defer policyContext.Destroy()

	ref, err := daemon.NewReference(digest.Digest(refID), ciRef) // Code above ensures that exactly one of (refID, ciRef) is set.
	if err != nil {
		return fmt.Errorf("Error preparing a docker-daemon: image reference: %v", err)
	}
	rawSource, err := daemon.NewOriginalOnlyImageSource(nil, ref, configDigest)
	if err != nil {
		return fmt.Errorf("Error preparing a docker-daemon: image source: %v", err)
	}
	defer rawSource.Close()
	unparsedOriginal := ciImage.UnparsedOriginalInstance(rawSource, nil)

	logrus.Debugf("Checking whether running %s is allowed…", transports.ImageName(ref))
	allowed, err := policyContext.IsRunningImageAllowed(unparsedOriginal)
	if !allowed {
		if err != nil {
			return fmt.Errorf("Running %s isn't allowed: %v", transports.ImageName(ref), err)
		}
		return fmt.Errorf("Running %s isn't allowed", transports.ImageName(ref))
	}
	if err != nil {
		return fmt.Errorf("Error evaluating policy for %s: %v", transports.ImageName(ref), err)
	}
	logrus.Debugf("… running allowed")
	return nil
}

func (daemon *Daemon) generateSecurityOpt(hostConfig *containertypes.HostConfig) ([]string, error) {
	for _, opt := range hostConfig.SecurityOpt {
		con := strings.Split(opt, "=")
		if con[0] == "label" {
			// Caller overrode SecurityOpts
			return nil, nil
		}
	}
	ipcMode := hostConfig.IpcMode
	pidMode := hostConfig.PidMode
	privileged := hostConfig.Privileged
	if ipcMode.IsHost() || pidMode.IsHost() || privileged {
		return label.DisableSecOpt(), nil
	}

	var ipcLabel []string
	var pidLabel []string
	ipcContainer := ipcMode.Container()
	pidContainer := pidMode.Container()
	if ipcContainer != "" {
		c, err := daemon.GetContainer(ipcContainer)
		if err != nil {
			return nil, err
		}
		ipcLabel = label.DupSecOpt(c.ProcessLabel)
		if pidContainer == "" {
			return ipcLabel, err
		}
	}
	if pidContainer != "" {
		c, err := daemon.GetContainer(pidContainer)
		if err != nil {
			return nil, err
		}

		pidLabel = label.DupSecOpt(c.ProcessLabel)
		if ipcContainer == "" {
			return pidLabel, err
		}
	}

	if pidLabel != nil && ipcLabel != nil {
		for i := 0; i < len(pidLabel); i++ {
			if pidLabel[i] != ipcLabel[i] {
				return nil, fmt.Errorf("--ipc and --pid containers SELinux labels aren't the same")
			}
		}
		return pidLabel, nil
	}
	return nil, nil
}

func (daemon *Daemon) setRWLayer(container *container.Container) error {
	var layerID layer.ChainID
	if container.ImageID != "" {
		img, err := daemon.imageStore.Get(container.ImageID)
		if err != nil {
			return err
		}
		layerID = img.RootFS.ChainID()
	}
	rwLayer, err := daemon.layerStore.CreateRWLayer(container.ID, layerID, container.MountLabel, daemon.setupInitLayer, container.HostConfig.StorageOpt)
	if err != nil {
		return err
	}
	container.RWLayer = rwLayer

	return nil
}

// VolumeCreate creates a volume with the specified name, driver, and opts
// This is called directly from the remote API
func (daemon *Daemon) VolumeCreate(name, driverName string, opts, labels map[string]string) (*types.Volume, error) {
	if name == "" {
		name = stringid.GenerateNonCryptoID()
	}

	v, err := daemon.volumes.Create(name, driverName, opts, labels)
	if err != nil {
		if volumestore.IsNameConflict(err) {
			return nil, fmt.Errorf("A volume named %s already exists. Choose a different volume name.", name)
		}
		return nil, err
	}

	daemon.LogVolumeEvent(v.Name(), "create", map[string]string{"driver": v.DriverName()})
	apiV := volumeToAPIType(v)
	apiV.Mountpoint = v.Path()
	return apiV, nil
}

func (daemon *Daemon) mergeAndVerifyConfig(config *containertypes.Config, img *image.Image) error {
	if img != nil && img.Config != nil {
		if err := merge(config, img.Config); err != nil {
			return err
		}
	}
	if len(config.Entrypoint) == 0 && len(config.Cmd) == 0 {
		return fmt.Errorf("No command specified")
	}
	return nil
}

// Checks if the client set configurations for more than one network while creating a container
func (daemon *Daemon) verifyNetworkingConfig(nwConfig *networktypes.NetworkingConfig) error {
	if nwConfig == nil || len(nwConfig.EndpointsConfig) <= 1 {
		return nil
	}
	l := make([]string, 0, len(nwConfig.EndpointsConfig))
	for k := range nwConfig.EndpointsConfig {
		l = append(l, k)
	}
	err := fmt.Errorf("Container cannot be connected to network endpoints: %s", strings.Join(l, ", "))
	return errors.NewBadRequestError(err)
}
