package daemon

import (
	"context"
	"fmt"
	"io"
	"io/ioutil"
	"os"

	"github.com/containers/image/docker/daemon/signatures"
	"github.com/containers/image/docker/tarfile"
	"github.com/containers/image/internal/tmpdir"
	"github.com/containers/image/manifest"
	"github.com/containers/image/types"
	"github.com/opencontainers/go-digest"
	"github.com/pkg/errors"
)

type daemonImageSource struct {
	ref             daemonReference
	*tarfile.Source // Implements most of types.ImageSource
	tarCopyPath     string
	sigsStore       *signatures.Store
	configDigest    digest.Digest // "" if not known yet
	// Private cache for readOriginals
	originalsRead      bool
	originalManifest   []byte   // Valid if originalsRead
	originalSignatures [][]byte // Valid if originalsRead
}

type layerInfo struct {
	path string
	size int64
}

// newImageSource returns a types.ImageSource for the specified image reference.
// The caller must call .Close() on the returned ImageSource.
//
// It would be great if we were able to stream the input tar as it is being
// sent; but Docker sends the top-level manifest, which determines which paths
// to look for, at the end, so in we will need to seek back and re-read, several times.
// (We could, perhaps, expect an exact sequence, assume that the first plaintext file
// is the config, and that the following len(RootFS) files are the layers, but that feels
// way too brittle.)
func newImageSource(ctx *types.SystemContext, ref daemonReference) (types.ImageSource, error) {
	c, err := newDockerClient(ctx)
	if err != nil {
		return nil, errors.Wrap(err, "Error initializing docker engine client")
	}
	// Per NewReference(), ref.StringWithinTransport() is either an image ID (config digest), or a !reference.NameOnly() reference.
	// Either way ImageSave should create a tarball with exactly one image.
	inputStream, err := c.ImageSave(context.TODO(), []string{ref.StringWithinTransport()})
	if err != nil {
		return nil, errors.Wrap(err, "Error loading image from docker engine")
	}
	defer inputStream.Close()

	// FIXME: use SystemContext here.
	tarCopyFile, err := ioutil.TempFile(tmpdir.TemporaryDirectoryForBigFiles(), "docker-daemon-tar")
	if err != nil {
		return nil, err
	}
	defer tarCopyFile.Close()

	succeeded := false
	defer func() {
		if !succeeded {
			os.Remove(tarCopyFile.Name())
		}
	}()

	if _, err := io.Copy(tarCopyFile, inputStream); err != nil {
		return nil, err
	}

	succeeded = true
	return &daemonImageSource{
		ref:           ref,
		Source:        tarfile.NewSource(tarCopyFile.Name()),
		tarCopyPath:   tarCopyFile.Name(),
		sigsStore:     signatures.NewStore(ctx),
		configDigest:  "",
		originalsRead: false,
	}, nil
}

// NewOriginalOnlyImageSource returns a types.ImageSource for the specified daemonReference,
// supporting only image.UnparsedOriginalInstance (in particular, GetBlob fails),
// and the caller must provide the config digest value.
// The caller must call .Close() on the returned ImageSource.
func NewOriginalOnlyImageSource(ctx *types.SystemContext, ref types.ImageReference, configDigest digest.Digest) (types.ImageSource, error) {
	dr, ok := ref.(daemonReference)
	if !ok {
		return nil, fmt.Errorf("daemon.NewOriginalOnlyImageSource called with a non-daemonReference value %#v", ref)
	}
	return &daemonImageSource{
		ref:           dr,
		Source:        tarfile.NewSource(""),
		tarCopyPath:   "",
		sigsStore:     signatures.NewStore(ctx),
		configDigest:  configDigest,
		originalsRead: false,
	}, nil
}

// Reference returns the reference used to set up this source, _as specified by the user_
// (not as the image itself, or its underlying storage, claims).  This can be used e.g. to determine which public keys are trusted for this image.
func (s *daemonImageSource) Reference() types.ImageReference {
	return s.ref
}

// Close removes resources associated with an initialized ImageSource, if any.
func (s *daemonImageSource) Close() error {
	if s.tarCopyPath != "" {
		if err := os.Remove(s.tarCopyPath); err != nil {
			return err
		}
	}
	return nil
}

// readOriginals returns the manifest and signatures stored in s.sigsStore, or (nil, nil, nil) if unavailable.
func (s *daemonImageSource) readOriginals() ([]byte, [][]byte, error) {
	if !s.originalsRead {
		if s.configDigest == "" {
			cd, err := s.Source.TarfileConfigDigest()
			if err != nil {
				return nil, nil, err
			}
			s.configDigest = cd
		}
		manifest, sigs, err := s.sigsStore.Read(s.configDigest, s.ref.ref) // s.ref.ref may be nil
		if err != nil {
			return nil, nil, err
		}
		s.originalManifest = manifest
		s.originalSignatures = sigs
		s.originalsRead = true
	}
	return s.originalManifest, s.originalSignatures, nil
}

// GetOriginalManifest returns the original manifest of the image (= the image used to write the image into this ImageReference),
// even if the image has been modified by the transport (e.g. uncompressing layers and throwing away the originals).
// For most transports, GetManifest() and GetOriginalManifest() should return the same data.
// If there is a difference, signatures returned by GetSignatures() should apply to GetOriginalManifest();
// OTOH there is NO EXPECTATION that image layers referenced by the original manifest will be accessible via GetBlob()
// (but the config blob, if any, _should_ be accessible).
func (s *daemonImageSource) GetOriginalManifest(instanceDigest *digest.Digest) ([]byte, string, error) {
	if instanceDigest != nil {
		// How did we even get here? GetOriginalManifest(nil) has returned a manifest.DockerV2Schema2MediaType.
		return nil, "", errors.Errorf(`Manifest lists are not supported by "docker-daemon:"`)
	}
	// This overrides s.Source.GetOriginalManifest, which just calls s.source.GetManifest.
	manifestBytes, _, err := s.readOriginals()
	if err != nil {
		return nil, "", err
	}
	if manifestBytes == nil {
		return nil, "", errors.New("The original manifest is not available")
	}
	return manifestBytes, manifest.DockerV2Schema2MediaType, nil // v2s2 is the only type we currently accept in Destination.PutManifest
}

// GetSignatures returns the image's signatures.  It may use a remote (= slow) service.
func (s *daemonImageSource) GetSignatures(ctx context.Context, instanceDigest *digest.Digest) ([][]byte, error) {
	if instanceDigest != nil {
		// How did we even get here? GetOriginalManifest(nil) has returned a manifest.DockerV2Schema2MediaType.
		return nil, errors.Errorf(`Manifest lists are not supported by "docker-daemon:"`)
	}
	// This overrides s.Source.GetSignatures, which just returns nothing.
	_, sigs, err := s.readOriginals()
	if err != nil {
		return nil, err
	}
	return sigs, nil
}
