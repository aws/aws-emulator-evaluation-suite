"""image-tag-immutable-mutation-rejected."""
from __future__ import annotations

import hashlib
import json
import os
import time

from behavioral_harness import tags

CHECK = "image-tag-immutable-mutation-rejected"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An IMMUTABLE repository rejects re-pushing a DIFFERENT image manifest under a tag
    that's already in use (ImageTagAlreadyExistsException); the original image stays bound
    to that tag, and pushing a genuinely NEW tag in the same repo still succeeds."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-immutable-")
    ecr.create_repository(
        repositoryName=repo_name,
        imageTagMutability="IMMUTABLE",
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_repo_verified(ecr, repo_name))

    original_digest = _push_minimal_image(ecr, repo_name, "v1")

    # Break exactly one thing: try to overwrite tag "v1" with a DIFFERENT manifest while the
    # repository enforces IMMUTABLE tags.
    code, message = _error(lambda: _push_minimal_image(ecr, repo_name, "v1"))
    assert code == "ImageTagAlreadyExistsException", (
        f"expected ImageTagAlreadyExistsException re-pushing tag 'v1' under an IMMUTABLE "
        f"repository, got {code!r}"
    )
    assert message == (
        f"The image tag 'v1' already exists in the '{repo_name}' repository and cannot be overwritten because the tag is immutable."
    ), message

    # Effect absent: tag "v1" still resolves to the ORIGINAL image digest, not a new one.
    detail_v1 = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": "v1"}])[
        "imageDetails"
    ][0]
    assert detail_v1["imageDigest"] == original_digest, (
        f"tag 'v1' resolves to {detail_v1['imageDigest']!r} after a rejected re-push; "
        f"expected it to still be the original digest {original_digest!r}"
    )

    # Positive control: pushing a genuinely NEW tag in the same IMMUTABLE repo still succeeds,
    # proving the rejection was specific to tag reuse and not a blanket denial.
    new_digest = _push_minimal_image(ecr, repo_name, "v2")
    detail_v2 = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": "v2"}])[
        "imageDetails"
    ][0]
    assert detail_v2["imageDigest"] == new_digest, (
        f"tag 'v2' resolves to {detail_v2['imageDigest']!r}, expected the freshly pushed "
        f"digest {new_digest!r}"
    )
    assert new_digest != original_digest, (
        f"pushing a genuinely new tag produced the same digest {new_digest!r} as the "
        f"original image; the two pushes embed distinct random content and must differ"
    )


def _sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repo_name: str, data: bytes) -> str:
    digest = f"sha256:{_sha256_hex(data)}"
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest])
    return digest


def _push_minimal_image(ecr, repo_name: str, tag: str) -> str:
    """Pushes a minimal, valid single-layer image and returns the resulting image digest.
    Each call embeds fresh random content, so repeated pushes are guaranteed distinct."""
    layer_bytes = b"sim2real-ecr-layer-" + os.urandom(16)
    layer_digest = _upload_blob(ecr, repo_name, layer_bytes)

    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
        "history": [{"created": "2024-01-01T00:00:00Z", "created_by": "sim2real"}],
    }
    config_bytes = json.dumps(config).encode("utf-8")
    config_digest = _upload_blob(ecr, repo_name, config_bytes)

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
    manifest_bytes = json.dumps(manifest).encode("utf-8")
    resp = ecr.put_image(
        repositoryName=repo_name, imageManifest=manifest_bytes.decode("utf-8"), imageTag=tag
    )
    return resp["image"]["imageId"]["imageDigest"]


def _error(fn):
    """Call fn(); return (code, message) of its ClientError. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_repo_verified(ecr, repo_name: str, timeout_s: float = 60) -> None:
    """force=True deletes a repository holding images. ctx.on_cleanup swallows exceptions, so
    print before raising -- otherwise a failed or incomplete delete leaks in silence."""
    from botocore.exceptions import ClientError

    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "RepositoryNotFoundException":
            return
        print(f"LEAK: delete_repository({repo_name}, force=True) failed with {code!r}")
        raise AssertionError(f"could not delete repository {repo_name}: {code!r}") from exc

    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            ecr.describe_repositories(repositoryNames=[repo_name])
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "RepositoryNotFoundException":
                return
            raise
        time.sleep(1.0)
    print(f"LEAK: repository {repo_name} still present {timeout_s}s after force delete")
    raise AssertionError(f"repository {repo_name} still present {timeout_s}s after force delete")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
