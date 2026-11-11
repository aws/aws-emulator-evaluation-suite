"""describe-image-signing-status-missing-image-rejected."""
from __future__ import annotations

import hashlib
import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-image-signing-status-missing-image-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeImageSigningStatus raises ImageNotFoundException for a digest that does
    not exist in an otherwise-real repository, and succeeds for a real image."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ctx, ecr)
    bogus_digest = "sha256:" + "0" * 64

    code, code_msg = _error(
        lambda: ecr.describe_image_signing_status(
            repositoryName=repo, imageId={"imageDigest": bogus_digest}
        )
    )
    assert code == "ImageNotFoundException", code
    expected_msg = (
        f"The image with imageId {{imageDigest:'{bogus_digest}', imageTag:'null'}} does not exist within the "
        f"repository with name '{repo}' in the registry with id '{ctx.account}'"
    )
    assert code_msg == expected_msg, f"expected message {expected_msg!r}, got {code_msg!r}"

    # Effect-absent control: that digest really is absent from the repository.
    list_resp = ecr.list_images(repositoryName=repo)
    present_digests = [i.get("imageDigest") for i in list_resp["imageIds"]]
    assert bogus_digest not in present_digests, present_digests

    # Positive control: a real, pushed image resolves successfully, resolves to that
    # exact image, and (with no signing configuration in this fresh repo) carries no
    # signing statuses.
    image = _push_minimal_image(ecr, repo, "present")
    resp = ecr.describe_image_signing_status(
        repositoryName=repo, imageId={"imageDigest": image["digest"]}
    )
    assert resp["imageId"]["imageDigest"] == image["digest"], resp.get("imageId")
    assert resp["signingStatuses"] == [], resp["signingStatuses"]


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ctx, ecr) -> str:
    name = ctx.unique_name("sim2real-ecr-behav-")
    ecr.create_repository(repositoryName=name)
    ctx.on_cleanup(lambda: _delete_repo_force(ecr, name))
    return name


def _delete_repo_force(ecr, name: str) -> None:
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _sha256_digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_blob(ecr, repo_name: str, data: bytes) -> str:
    digest = _sha256_digest(data)
    upload = ecr.initiate_layer_upload(repositoryName=repo_name)
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload["uploadId"],
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload["uploadId"], layerDigests=[digest]
    )
    return digest


def _push_minimal_image(ecr, repo_name: str, tag: str) -> dict:
    config_bytes = json.dumps(
        {
            "architecture": "amd64",
            "os": "linux",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": []},
        }
    ).encode()
    layer_bytes = f"sim2real-ecr-behavioral-layer-blob-{tag}".encode()
    config_digest = _upload_blob(ecr, repo_name, config_bytes)
    layer_digest = _upload_blob(ecr, repo_name, layer_bytes)
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
    manifest_bytes = json.dumps(manifest).encode()
    resp = ecr.put_image(
        repositoryName=repo_name, imageManifest=manifest_bytes.decode(), imageTag=tag
    )
    image = resp["image"]
    return {
        "digest": image["imageId"]["imageDigest"],
        "tag": tag,
        "manifest_bytes": manifest_bytes,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
