"""Tests for Docker image validation and hardening (fix/round3 item 1)."""

import pytest
from scanners.docker_scanner import validate_image, scan_docker_image


REJECTED_IMAGES = [
    "--input=/etc/passwd",
    "--config=/tmp/x",
    "-o /tmp/p",
    "registry.internal:5000/a/b",
    "169.254.169.254/x:latest",
    "alpine; id",
    "$(id)",
    "localhost/x",
    "http://docker.io/alpine",
    "quay.io:443/coreos/etcd",
    "a" * 256,
]

ACCEPTED_IMAGES = [
    "alpine:3.19",
    "node:14",
    "python:3.7",
    "custom-service:latest",
    "docker.io/library/alpine:3.19",
    "ghcr.io/org/app@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    "quay.io/coreos/etcd:v3.5.0",
]


class TestDockerImageValidation:
    @pytest.mark.parametrize("img", REJECTED_IMAGES)
    def test_rejected_images_fail_validation(self, img):
        with pytest.raises(ValueError):
            validate_image(img)

    @pytest.mark.parametrize("img", REJECTED_IMAGES)
    def test_scan_docker_image_rejects_malicious_inputs(self, img):
        with pytest.raises(ValueError):
            scan_docker_image(img)

    @pytest.mark.parametrize("img", ACCEPTED_IMAGES)
    def test_accepted_images_pass_validation(self, img):
        assert validate_image(img) == img
