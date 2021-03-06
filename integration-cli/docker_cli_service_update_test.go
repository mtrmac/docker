// +build !windows

package main

import (
	"encoding/json"
	"fmt"

	"github.com/docker/docker/api/types/swarm"
	"github.com/docker/docker/pkg/integration/checker"
	"github.com/go-check/check"
)

func (s *DockerSwarmSuite) TestServiceUpdatePort(c *check.C) {
	d := s.AddDaemon(c, true, true)

	serviceName := "TestServiceUpdatePort"
	serviceArgs := append([]string{"service", "create", "--name", serviceName, "-p", "8080:8081", defaultSleepImage}, sleepCommandForDaemonPlatform()...)

	// Create a service with a port mapping of 8080:8081.
	out, err := d.Cmd(serviceArgs...)
	c.Assert(err, checker.IsNil)
	waitAndAssert(c, defaultReconciliationTimeout, d.checkActiveContainerCount, checker.Equals, 1)

	// Update the service: changed the port mapping from 8080:8081 to 8082:8083.
	_, err = d.Cmd("service", "update", "--publish-add", "8082:8083", "--publish-rm", "8081", serviceName)
	c.Assert(err, checker.IsNil)

	// Inspect the service and verify port mapping
	expected := []swarm.PortConfig{
		{
			Protocol:      "tcp",
			PublishedPort: 8082,
			TargetPort:    8083,
			PublishMode:   "ingress",
		},
	}

	out, err = d.Cmd("service", "inspect", "--format", "{{ json .Spec.EndpointSpec.Ports }}", serviceName)
	c.Assert(err, checker.IsNil)

	var portConfig []swarm.PortConfig
	if err := json.Unmarshal([]byte(out), &portConfig); err != nil {
		c.Fatalf("invalid JSON in inspect result: %v (%s)", err, out)
	}
	c.Assert(portConfig, checker.DeepEquals, expected)
}

func (s *DockerSwarmSuite) TestServiceUpdateLabel(c *check.C) {
	d := s.AddDaemon(c, true, true)
	out, err := d.Cmd("service", "create", "--name=test", "busybox", "top")
	c.Assert(err, checker.IsNil, check.Commentf(out))
	service := d.getService(c, "test")
	c.Assert(service.Spec.Labels, checker.HasLen, 0)

	// add label to empty set
	out, err = d.Cmd("service", "update", "test", "--label-add", "foo=bar")
	c.Assert(err, checker.IsNil, check.Commentf(out))
	service = d.getService(c, "test")
	c.Assert(service.Spec.Labels, checker.HasLen, 1)
	c.Assert(service.Spec.Labels["foo"], checker.Equals, "bar")

	// add label to non-empty set
	out, err = d.Cmd("service", "update", "test", "--label-add", "foo2=bar")
	c.Assert(err, checker.IsNil, check.Commentf(out))
	service = d.getService(c, "test")
	c.Assert(service.Spec.Labels, checker.HasLen, 2)
	c.Assert(service.Spec.Labels["foo2"], checker.Equals, "bar")

	out, err = d.Cmd("service", "update", "test", "--label-rm", "foo2")
	c.Assert(err, checker.IsNil, check.Commentf(out))
	service = d.getService(c, "test")
	c.Assert(service.Spec.Labels, checker.HasLen, 1)
	c.Assert(service.Spec.Labels["foo2"], checker.Equals, "")

	out, err = d.Cmd("service", "update", "test", "--label-rm", "foo")
	c.Assert(err, checker.IsNil, check.Commentf(out))
	service = d.getService(c, "test")
	c.Assert(service.Spec.Labels, checker.HasLen, 0)
	c.Assert(service.Spec.Labels["foo"], checker.Equals, "")

	// now make sure we can add again
	out, err = d.Cmd("service", "update", "test", "--label-add", "foo=bar")
	c.Assert(err, checker.IsNil, check.Commentf(out))
	service = d.getService(c, "test")
	c.Assert(service.Spec.Labels, checker.HasLen, 1)
	c.Assert(service.Spec.Labels["foo"], checker.Equals, "bar")
}

func (s *DockerSwarmSuite) TestServiceUpdateSecrets(c *check.C) {
	d := s.AddDaemon(c, true, true)
	testName := "test_secret"
	id := d.createSecret(c, swarm.SecretSpec{
		swarm.Annotations{
			Name: testName,
		},
		[]byte("TESTINGDATA"),
	})
	c.Assert(id, checker.Not(checker.Equals), "", check.Commentf("secrets: %s", id))
	testTarget := "testing"
	serviceName := "test"

	out, err := d.Cmd("service", "create", "--name", serviceName, "busybox", "top")
	c.Assert(err, checker.IsNil, check.Commentf(out))

	// add secret
	out, err = d.cmdRetryOutOfSequence("service", "update", "test", "--secret-add", fmt.Sprintf("source=%s,target=%s", testName, testTarget))
	c.Assert(err, checker.IsNil, check.Commentf(out))

	out, err = d.Cmd("service", "inspect", "--format", "{{ json .Spec.TaskTemplate.ContainerSpec.Secrets }}", serviceName)
	c.Assert(err, checker.IsNil)

	var refs []swarm.SecretReference
	c.Assert(json.Unmarshal([]byte(out), &refs), checker.IsNil)
	c.Assert(refs, checker.HasLen, 1)

	c.Assert(refs[0].SecretName, checker.Equals, testName)
	c.Assert(refs[0].Target, checker.Not(checker.IsNil))
	c.Assert(refs[0].Target.Name, checker.Equals, testTarget)

	// remove
	out, err = d.cmdRetryOutOfSequence("service", "update", "test", "--secret-rm", testName)
	c.Assert(err, checker.IsNil, check.Commentf(out))

	out, err = d.Cmd("service", "inspect", "--format", "{{ json .Spec.TaskTemplate.ContainerSpec.Secrets }}", serviceName)
	c.Assert(err, checker.IsNil)

	c.Assert(json.Unmarshal([]byte(out), &refs), checker.IsNil)
	c.Assert(refs, checker.HasLen, 0)
}
