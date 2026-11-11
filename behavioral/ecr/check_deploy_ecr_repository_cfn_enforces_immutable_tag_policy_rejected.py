"""deploy-ecr-repository-cfn-enforces-immutable-tag-policy-rejected."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-ecr-repository-cfn-enforces-immutable-tag-policy-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A repository deployed via CloudFormation with ImageTagMutability=IMMUTABLE
    actually rejects a retag attempt at runtime -- the deployed property is
    enforced by the data plane, not merely stored as metadata."""
    ecr = ctx.client("ecr")
    cfn = ctx.client("cloudformation")

    repo_name = ctx.unique_name("sim2real-ecr-immut-")
    stack_name = ctx.unique_name("sim2real-ecr-immut-stack-")
    template = json.dumps(
        {
            "Resources": {
                "Repo": {
                    "Type": "AWS::ECR::Repository",
                    "Properties": {
                        "RepositoryName": repo_name,
                        "ImageTagMutability": "IMMUTABLE",
                        "EmptyOnDelete": True,
                    },
                }
            }
        }
    )

    cfn.create_stack(StackName=stack_name, TemplateBody=template)
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )

    described = ecr.describe_repositories(repositoryNames=[repo_name])["repositories"][0]
    assert described["imageTagMutability"] == "IMMUTABLE", (
        f"expected imageTagMutability=IMMUTABLE from the CFN-deployed repo, "
        f"got {described['imageTagMutability']!r}"
    )

    image_a = _push_minimal_image(ctx, repo_name, "v1")
    digest_a = image_a["imageId"]["imageDigest"]

    code, code_msg = _error(
        lambda: _push_minimal_image(
            ctx, repo_name, "v1", config_extra={"comment": "variant-b-retag"}
        )
    )
    assert code == "ImageTagAlreadyExistsException", (
        f"expected ImageTagAlreadyExistsException retagging 'v1' on an IMMUTABLE "
        f"repo, got {code!r}"
    )
    expected_msg = (
        f"The image tag 'v1' already exists in the '{repo_name}' repository and cannot be "
        "overwritten because the tag is immutable."
    )
    assert code_msg == expected_msg, f"expected message {expected_msg!r}, got {code_msg!r}"

    # Effect absent: tag "v1" must still point at the original digest.
    still = ecr.batch_get_image(repositoryName=repo_name, imageIds=[{"imageTag": "v1"}])
    still_digest = still["images"][0]["imageId"]["imageDigest"]
    assert still_digest == digest_a, (
        f"expected tag 'v1' to still point at the original digest {digest_a!r} "
        f"after the rejected retag, got {still_digest!r}"
    )

    # Positive control: the SAME differing content pushed under a NEW tag
    # succeeds -- immutability only blocks reusing an existing tag.
    image_b = _push_minimal_image(
        ctx, repo_name, "v2", config_extra={"comment": "variant-b-retag"}
    )
    digest_b = image_b["imageId"]["imageDigest"]
    assert digest_b != digest_a, (
        f"expected the v2 push (different content) to produce a digest distinct "
        f"from v1's {digest_a!r}, got the same digest {digest_b!r}"
    )
    fetched_v2 = ecr.batch_get_image(repositoryName=repo_name, imageIds=[{"imageTag": "v2"}])
    fetched_v2_digest = fetched_v2["images"][0]["imageId"]["imageDigest"]
    assert fetched_v2_digest == digest_b, (
        f"expected tag 'v2' to resolve to the pushed digest {digest_b!r}, "
        f"got {fetched_v2_digest!r}"
    )


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150}
    )


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _upload_blob(ecr, repo_name: str, blob_bytes: bytes) -> tuple[str, int]:
    digest = "sha256:" + hashlib.sha256(blob_bytes).hexdigest()
    avail = ecr.batch_check_layer_availability(
        repositoryName=repo_name, layerDigests=[digest]
    )
    if avail["layers"] and avail["layers"][0]["layerAvailability"] == "AVAILABLE":
        return digest, avail["layers"][0]["layerSize"]
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(blob_bytes) - 1,
        layerPartBlob=blob_bytes,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest, len(blob_bytes)


def _push_minimal_image(ctx, repo_name: str, tag: str, config_extra: dict | None = None):
    ecr = ctx.client("ecr")

    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w"):
        pass
    tar_bytes = tar_buf.getvalue()
    gz_buf = io.BytesIO()
    with gzip.GzipFile(fileobj=gz_buf, mode="wb", mtime=0) as gz:
        gz.write(tar_bytes)
    gz_bytes = gz_buf.getvalue()

    layer_digest, layer_size = _upload_blob(ecr, repo_name, gz_bytes)
    diff_id = "sha256:" + hashlib.sha256(tar_bytes).hexdigest()

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        "history": [{"created": "2024-01-01T00:00:00Z"}],
    }
    if config_extra:
        config.update(config_extra)
    config_bytes = json.dumps(config).encode("utf-8")
    config_digest, config_size = _upload_blob(ecr, repo_name, config_bytes)

    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": config_size,
            "digest": config_digest,
        },
        "layers": [
            {
                "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
                "size": layer_size,
                "digest": layer_digest,
            }
        ],
    }
    resp = ecr.put_image(
        repositoryName=repo_name, imageManifest=json.dumps(manifest), imageTag=tag
    )
    return resp["image"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
