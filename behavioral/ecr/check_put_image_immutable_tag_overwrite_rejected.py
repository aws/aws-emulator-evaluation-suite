"""put-image-immutable-tag-overwrite-rejected."""
from __future__ import annotations

import gzip
import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-image-immutable-tag-overwrite-rejected"
GROUP = "overly-permissive"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Pushing a different manifest to an existing tag on an IMMUTABLE repository raises
    ImageTagAlreadyExistsException, keeps the tag's original digest, and a new tag still pushes."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-immutable-")
    ecr.create_repository(
        repositoryName=repo_name,
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    ecr.put_image_tag_mutability(repositoryName=repo_name, imageTagMutability="IMMUTABLE")

    digest_a, _ = _push_test_image(ecr, repo_name, "v1", seed=b"payload-a")

    code, message = _error_code(lambda: _push_test_image(ecr, repo_name, "v1", seed=b"payload-b"))
    assert code == "ImageTagAlreadyExistsException", (
        f"expected ImageTagAlreadyExistsException overwriting an IMMUTABLE tag, got {code!r}"
    )
    expected_message = (
        f"The image tag 'v1' already exists in the '{repo_name}' repository and cannot be overwritten "
        f"because the tag is immutable."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: tag v1 still points at the original digest, unchanged
    details_v1 = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": "v1"}])["imageDetails"]
    assert len(details_v1) == 1, f"expected exactly one image for tag v1, got {len(details_v1)}"
    assert details_v1[0]["imageDigest"] == digest_a, (
        f"expected tag v1 to still point at {digest_a}, found {details_v1[0]['imageDigest']}"
    )

    # positive control: pushing a new manifest under a *different* tag still succeeds
    digest_c, _ = _push_test_image(ecr, repo_name, "v2", seed=b"payload-c")
    details_v2 = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageTag": "v2"}])["imageDetails"]
    assert len(details_v2) == 1, f"expected exactly one image for tag v2, got {len(details_v2)}"
    assert details_v2[0]["imageDigest"] == digest_c, (
        f"expected tag v2 to point at {digest_c}, found {details_v2[0]['imageDigest']}"
    )
    assert digest_c != digest_a, f"expected v2's digest to differ from v1's, both were {digest_a}"


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises,
    so a target accepting a call real AWS refuses cannot read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _upload_blob(ecr, repo_name: str, data: bytes) -> str:
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    upload = ecr.initiate_layer_upload(repositoryName=repo_name)
    upload_id = upload["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest])
    return digest


def _push_test_image(ecr, repo_name: str, tag: str, *, seed: bytes):
    layer_bytes = gzip.compress(b"sim2real-ecr-behavioral-layer:" + seed)
    layer_digest = _upload_blob(ecr, repo_name, layer_bytes)
    config_bytes = json.dumps({
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
    }).encode("utf-8")
    config_digest = _upload_blob(ecr, repo_name, config_bytes)
    manifest = {
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": len(config_bytes),
            "digest": config_digest,
        },
        "layers": [{
            "mediaType": "application/vnd.docker.image.rootfs.diff.tar.gzip",
            "size": len(layer_bytes),
            "digest": layer_digest,
        }],
    }
    manifest_text = json.dumps(manifest)
    resp = ecr.put_image(repositoryName=repo_name, imageManifest=manifest_text, imageTag=tag)
    return resp["image"]["imageId"]["imageDigest"], manifest_text


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
