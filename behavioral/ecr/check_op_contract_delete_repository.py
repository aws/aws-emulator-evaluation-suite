"""op-contract-deleteRepository."""
from __future__ import annotations

import hashlib
import json
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-deleteRepository"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteRepository deletes an empty repository (then RepositoryNotFoundException), refuses
    one holding an image with RepositoryNotEmptyException and leaves it, and deletes it with
    force=True; each refusal carries the exact message."""
    ecr = ctx.client("ecr")

    # Positive path: empty repository deletes cleanly.
    empty_repo = _create_repo(ctx)
    empty_name = empty_repo["repositoryName"]
    resp = ecr.delete_repository(repositoryName=empty_name)
    assert resp["repository"]["repositoryName"] == empty_name, (
        f"expected DeleteRepository to echo {empty_name!r}, got "
        f"{resp['repository']['repositoryName']!r}"
    )
    code, code_msg = _error(lambda: ecr.describe_repositories(repositoryNames=[empty_name]))
    assert code == "RepositoryNotFoundException", (
        f"expected DescribeRepositories on a deleted empty repo to raise "
        f"RepositoryNotFoundException, got {code!r}"
    )
    expected_msg = f"The repository with name '{empty_name}' does not exist in the registry with id '{ctx.account}'"
    assert code_msg == expected_msg, f"expected message {expected_msg!r}, got {code_msg!r}"

    # Negative: non-empty repository refuses deletion without force.
    busy_repo = _create_repo(ctx)
    busy_name = busy_repo["repositoryName"]
    _push_minimal_image(ctx, busy_name, "occupied", seed=b"non-empty")

    code, code_msg = _error(lambda: ecr.delete_repository(repositoryName=busy_name))
    assert code == "RepositoryNotEmptyException", (
        f"expected DeleteRepository without force on a non-empty repo to raise "
        f"RepositoryNotEmptyException, got {code!r}"
    )
    expected_msg = f"The repository with name '{busy_name}' in registry with id '{ctx.account}' cannot be deleted because it still contains images"
    assert code_msg == expected_msg, f"expected message {expected_msg!r}, got {code_msg!r}"
    # Effect absent: repository still exists and is still describable.
    still_there = ecr.describe_repositories(repositoryNames=[busy_name])["repositories"]
    assert still_there[0]["repositoryName"] == busy_name, (
        f"expected {busy_name!r} to still exist after the rejected delete, "
        f"got {still_there[0]['repositoryName']!r}"
    )

    # Positive control: force=True clears the same precondition and succeeds.
    force_resp = ecr.delete_repository(repositoryName=busy_name, force=True)
    assert force_resp["repository"]["repositoryName"] == busy_name, (
        f"expected DeleteRepository(force=True) to echo {busy_name!r}, got "
        f"{force_resp['repository']['repositoryName']!r}"
    )
    code, code_msg = _error(lambda: ecr.describe_repositories(repositoryNames=[busy_name]))
    assert code == "RepositoryNotFoundException", (
        f"expected DescribeRepositories on the force-deleted repo to raise "
        f"RepositoryNotFoundException, got {code!r}"
    )
    expected_msg = f"The repository with name '{busy_name}' does not exist in the registry with id '{ctx.account}'"
    assert code_msg == expected_msg, f"expected message {expected_msg!r}, got {code_msg!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ctx, **kwargs: Any) -> dict:
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-ecr-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: _delete_repo_if_present(ecr, name))
    return resp["repository"]


def _delete_repo_if_present(ecr, name: str) -> None:
    """Teardown: force-delete the repository, tolerating one the check already deleted."""
    try:
        ecr.delete_repository(repositoryName=name, force=True)
    except ClientError as err:
        if err.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


def _upload_blob(ctx, repo_name: str, data: bytes) -> str:
    ecr = ctx.client("ecr")
    digest = _digest(data)
    upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(
        repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
    )
    return digest


def _push_minimal_image(ctx, repo_name: str, tag: str, seed: bytes = b"") -> dict:
    ecr = ctx.client("ecr")
    config_bytes = json.dumps(
        {
            "architecture": "amd64",
            "config": {},
            "rootfs": {"type": "layers", "diff_ids": []},
            "seed": seed.decode() if seed else "",
        }
    ).encode()
    layer_bytes = b"sim2real-ecr-layer-" + (seed or b"data") + b"-" * 16
    config_digest = _upload_blob(ctx, repo_name, config_bytes)
    layer_digest = _upload_blob(ctx, repo_name, layer_bytes)
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
    manifest_str = json.dumps(manifest)
    resp = ecr.put_image(
        repositoryName=repo_name, imageManifest=manifest_str, imageTag=tag
    )
    return {
        "digest": resp["image"]["imageId"]["imageDigest"],
        "manifest": manifest_str,
        "layer_digest": layer_digest,
        "layer_size": len(layer_bytes),
        "config_digest": config_digest,
        "config_size": len(config_bytes),
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
