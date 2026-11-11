"""e2e-storage-class-and-replication-flow."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "e2e-storage-class-and-replication-flow"
GROUP = "e2e"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """An image's replication status is queryable while ACTIVE and after it moves to ARCHIVE, and
    DescribeImages reflects the storage-class change."""
    ecr = ctx.client("ecr")
    repo = _create_repo(ctx)

    pushed = _push_image(ctx, repo["repositoryName"], tag="v1")
    digest = pushed["imageId"]["imageDigest"]

    active_detail = _describe_one_image(ecr, repo["repositoryName"], digest)
    assert active_detail["imageStatus"] == "ACTIVE", f"expected ACTIVE, got {active_detail['imageStatus']!r}"

    active_replication = ecr.describe_image_replication_status(
        repositoryName=repo["repositoryName"], imageId={"imageDigest": digest}
    )
    assert active_replication["replicationStatuses"] == [], (
        f"expected no replication statuses with no replication configured, "
        f"got {active_replication['replicationStatuses']!r}"
    )

    archive_resp = ecr.update_image_storage_class(
        repositoryName=repo["repositoryName"],
        imageId={"imageDigest": digest},
        targetStorageClass="ARCHIVE",
    )
    assert archive_resp["imageStatus"] == "ARCHIVED", (
        f"expected UpdateImageStorageClass to report ARCHIVED, got {archive_resp['imageStatus']!r}"
    )

    archived_detail = _poll_until(
        lambda: _describe_one_image(ecr, repo["repositoryName"], digest),
        lambda d: d["imageStatus"] == "ARCHIVED",
        timeout_s=60.0,
    )
    assert archived_detail["imageStatus"] == "ARCHIVED", (
        f"expected DescribeImages to reflect ARCHIVED within 60s, got {archived_detail['imageStatus']!r}"
    )
    assert "lastArchivedAt" in archived_detail, f"expected lastArchivedAt on archived image, got {archived_detail!r}"

    # replication-status queries keep working end-to-end after the storage-class change
    archived_replication = ecr.describe_image_replication_status(
        repositoryName=repo["repositoryName"], imageId={"imageDigest": digest}
    )
    assert archived_replication["replicationStatuses"] == [], (
        f"expected no replication statuses after archiving with no replication configured, "
        f"got {archived_replication['replicationStatuses']!r}"
    )

    ecr.delete_repository(repositoryName=repo["repositoryName"], force=True)
    code, message = _error(
        lambda: ecr.describe_repositories(repositoryNames=[repo["repositoryName"]])
    )
    assert code == "RepositoryNotFoundException", f"expected RepositoryNotFoundException on a deleted repo, got {code!r}"
    expected = f"The repository with name '{repo['repositoryName']}' does not exist in the registry with id '{ctx.account}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    mutate_code, mutate_message = _error(
        lambda: ecr.update_image_storage_class(
            repositoryName=repo["repositoryName"],
            imageId={"imageDigest": digest},
            targetStorageClass="ARCHIVE",
        )
    )
    assert mutate_code == "RepositoryNotFoundException", (
        f"expected a mutation on the deleted repo to also fail with RepositoryNotFoundException, got {mutate_code!r}"
    )
    expected = f"The repository with name '{repo['repositoryName']}' does not exist in the registry with id '{ctx.account}'"
    assert mutate_message == expected, f"expected message {expected!r}, got {mutate_message!r}"


import hashlib
import json
import time

_MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"
_CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"
_LAYER_MEDIA_TYPE = "application/vnd.docker.image.rootfs.diff.tar.gzip"


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses cannot read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_repo(ctx, **kwargs):
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-ecr-arch-")
    resp = ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: _delete_repo_if_exists(ecr, name))
    return resp["repository"]


def _delete_repo_if_exists(ecr, repo_name):
    from botocore.exceptions import ClientError

    try:
        ecr.delete_repository(repositoryName=repo_name, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "RepositoryNotFoundException":
            raise


def _describe_one_image(ecr, repo_name, digest):
    resp = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageDigest": digest}])
    return resp["imageDetails"][0]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition never satisfied within {timeout_s}s, last value={value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _upload_blob(ecr, repo_name, data):
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
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


def _push_image(ctx, repo_name, tag=None):
    ecr = ctx.client("ecr")
    unique = f"{repo_name}-{time.time_ns()}"
    config_bytes = json.dumps(
        {"architecture": "amd64", "config": {}, "rootfs": {"type": "layers", "diff_ids": []}, "unique": unique}
    ).encode()
    layer_bytes = f"sim2real-ecr-layer-{unique}".encode()
    config_digest = _upload_blob(ecr, repo_name, config_bytes)
    layer_digest = _upload_blob(ecr, repo_name, layer_bytes)
    manifest = {
        "schemaVersion": 2,
        "mediaType": _MANIFEST_MEDIA_TYPE,
        "config": {"mediaType": _CONFIG_MEDIA_TYPE, "size": len(config_bytes), "digest": config_digest},
        "layers": [{"mediaType": _LAYER_MEDIA_TYPE, "size": len(layer_bytes), "digest": layer_digest}],
    }
    kwargs = {"repositoryName": repo_name, "imageManifest": json.dumps(manifest)}
    if tag:
        kwargs["imageTag"] = tag
    return ecr.put_image(**kwargs)["image"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
