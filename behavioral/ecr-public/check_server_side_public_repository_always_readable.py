"""server-side-public-repository-always-readable."""
from __future__ import annotations

import gzip
import hashlib
import json
from typing import Any

from behavioral_harness import tags

CHECK = "server-side-public-repository-always-readable"
GROUP = "server-side"
SERVICES = ["ecr-public"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A push-only Allow repository policy does not revoke the owner's DescribeImages or
    GetAuthorizationToken, and a policy whose Effect is outside {"Allow","Deny"} is rejected.

    Reference: https://docs.aws.amazon.com/AmazonECR/latest/public/public-repository-policies.html
    """
    ecrp = _regional_client(ctx, "ecr-public")
    # An explicit Deny naming the caller's own principal is not exercised: normal IAM evaluation
    # blocks it, so it would not test the additive-policy behaviour.
    repo_name = ctx.unique_name("sim2real-behav-pubread-")
    ecrp.create_repository(
        repositoryName=repo_name,
        tags=[
            {"Key": "sim2real-managed", "Value": "true"},
            {"Key": "sim2real-check", "Value": CHECK},
        ],
    )
    ctx.on_cleanup(lambda: ecrp.delete_repository(repositoryName=repo_name, force=True))

    # Use the caller's own (real, existing) account root as the policy's Principal --
    # a syntactically-valid but non-existent IAM user/role ARN is itself rejected by this
    # API's policy validator, so pin the confound down with an ARN guaranteed to resolve.
    sts = _regional_client(ctx, "sts")
    caller_account = sts.get_caller_identity()["Account"]
    principal_root_arn = f"arn:aws:iam::{caller_account}:root"

    config_bytes = json.dumps({"architecture": "amd64", "os": "linux", "config": {}}).encode()
    layer_bytes = gzip.compress(b"sim2real-behav-pubread-layer")
    config_digest = _upload_blob(ecrp, repo_name, config_bytes)
    layer_digest = _upload_blob(ecrp, repo_name, layer_bytes)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": len(layer_bytes),
                "digest": layer_digest,
            }
        ],
    }
    tag = ctx.unique_name("sim2real-behav-tag-")[:120]
    ecrp.put_image(
        repositoryName=repo_name,
        imageManifest=json.dumps(manifest),
        imageTag=tag,
        imageManifestMediaType="application/vnd.docker.distribution.manifest.v2+json",
    )

    baseline = ecrp.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": tag}])
    baseline_digest = baseline["imageDetails"][0]["imageDigest"]

    # (1) A restrictive-but-valid Allow-only policy -- granting push to a principal that
    # never explicitly gets read -- is accepted and persisted...
    restrictive_allow_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowPushOnly",
                "Effect": "Allow",
                "Principal": {"AWS": principal_root_arn},
                "Action": [
                    "ecr-public:BatchCheckLayerAvailability",
                    "ecr-public:PutImage",
                    "ecr-public:InitiateLayerUpload",
                    "ecr-public:UploadLayerPart",
                    "ecr-public:CompleteLayerUpload",
                ],
            }
        ],
    }
    ecrp.set_repository_policy(
        repositoryName=repo_name, policyText=json.dumps(restrictive_allow_policy)
    )
    ctx.on_cleanup(lambda: ecrp.delete_repository_policy(repositoryName=repo_name))

    persisted = ecrp.get_repository_policy(repositoryName=repo_name)
    assert json.loads(persisted["policyText"]) == restrictive_allow_policy, (
        f"restrictive policy was not persisted as given: {persisted['policyText']!r}"
    )

    # ...and has NO effect on the owner's own read access: DescribeImages still
    # succeeds and returns the exact same image, even though no principal was ever
    # explicitly granted read in the resource policy.
    after = ecrp.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": tag}])
    assert len(after["imageDetails"]) == 1
    assert after["imageDetails"][0]["imageDigest"] == baseline_digest

    # A caller can still obtain a working pull credential regardless of the repo-level
    # policy never granting anyone explicit read.
    token = ecrp.get_authorization_token()["authorizationData"]["authorizationToken"]
    assert isinstance(token, str) and len(token) > 0

    # (2) Overly-permissive boundary: an Effect value outside the {"Allow","Deny"}
    # enum is rejected outright -- the server validates the policy grammar itself
    # rather than accepting any well-formed-JSON blob as a valid policy.
    invalid_action_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "InvalidEffectValue",
                "Effect": "Permit",
                "Principal": {"AWS": principal_root_arn},
                "Action": ["ecr-public:DescribeImages"],
            }
        ],
    }
    invalid_err = _error(
        lambda: ecrp.set_repository_policy(
            repositoryName=repo_name, policyText=json.dumps(invalid_action_policy)
        )
    )
    expected = ("InvalidParameterException", "Invalid parameter at 'PolicyText' failed to satisfy constraint: 'Invalid repository policy provided'")
    assert (invalid_err.get("Code"), invalid_err.get("Message")) == expected, (
        f"expected a policy with an invalid Effect value to be rejected with {expected}, got {invalid_err!r}"
    )

    # The rejected call must not have replaced the policy already in place.
    still_persisted = ecrp.get_repository_policy(repositoryName=repo_name)
    assert json.loads(still_persisted["policyText"]) == restrictive_allow_policy, (
        "the rejected invalid-action policy must not have overwritten the existing policy"
    )


def _error(fn):
    """Call fn() and return the AWS Error dict (Code, Message); an unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        resp = fn()
    except ClientError as err:
        return err.response["Error"]
    raise AssertionError(f"expected the call to be refused but it SUCCEEDED with {resp!r}")


def _upload_blob(ecrp: Any, repo_name: str, content: bytes) -> str:
    digest = "sha256:" + hashlib.sha256(content).hexdigest()
    upload_id = ecrp.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecrp.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(content) - 1,
        layerPartBlob=content,
    )
    ecrp.complete_layer_upload(repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest])
    return digest


def _regional_client(ctx, service: str, region: str = "us-east-1"):
    """ecr-public is operable only in us-east-1, so pin that region on the target ctx names."""
    from botocore.config import Config

    return ctx.client(service, region=region, config=Config(retries={"max_attempts": 8, "mode": "standard"}))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
