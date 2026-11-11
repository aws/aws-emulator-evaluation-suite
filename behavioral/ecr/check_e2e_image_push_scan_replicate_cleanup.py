"""e2e-image-push-scan-replicate-cleanup."""
from __future__ import annotations

import hashlib
import io
import json
import tarfile
import time
import uuid

from behavioral_harness import tags

CHECK = "e2e-image-push-scan-replicate-cleanup"
GROUP = "e2e"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:ecr-replication")
def run(ctx) -> None:
    """Push a real image, scan it to completion, enable registry replication scoped to this
    repository and observe DescribeImageReplicationStatus reflect that specific configured
    destination for that image, then force-delete the repository and confirm it 404s."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    repo_name = ctx.unique_name("sim2real-ecr-e2e-").lower()
    ecr.create_repository(
        repositoryName=repo_name,
        tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    repo_deleted = {"done": False}

    def _cleanup_repo():
        if repo_deleted["done"]:
            return
        try:
            ecr.delete_repository(repositoryName=repo_name, force=True)
        except ecr.exceptions.RepositoryNotFoundException:
            pass

    ctx.on_cleanup(_cleanup_repo)

    # --- replication must be configured for this repository *before* an image is
    # pushed: Amazon ECR only replicates content pushed/restored after the rule takes
    # effect, never retroactively. So we configure replication first, then push. ---
    dest_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    original_replication = ecr.describe_registry()["replicationConfiguration"]
    original_rules = list(original_replication.get("rules", []))

    def _restore_replication():
        ecr.put_replication_configuration(replicationConfiguration={"rules": original_rules})

    ctx.on_cleanup(_restore_replication)

    new_rule = {
        "destinations": [{"region": dest_region, "registryId": account_id}],
        "repositoryFilters": [{"filter": repo_name, "filterType": "PREFIX_MATCH"}],
    }
    ecr.put_replication_configuration(
        replicationConfiguration={"rules": original_rules + [new_rule]}
    )

    digest = _push_minimal_image(ecr, repo_name, "v1")

    # --- scan ---
    # Our pushed image is a minimal synthetic layer with no recognizable OS -- Amazon
    # ECR basic scanning does not support the Docker "scratch" pattern, so it
    # legitimately reports a terminal FAILED/UNSUPPORTED_IMAGE outcome with a
    # descriptive reason rather than COMPLETE; that is still the scan pipeline
    # reaching a real terminal state, which is what this check verifies.
    ecr.start_image_scan(repositoryName=repo_name, imageId={"imageDigest": digest})
    scan_result = _poll_until(
        lambda: ecr.describe_image_scan_findings(
            repositoryName=repo_name, imageId={"imageDigest": digest}
        )["imageScanStatus"],
        lambda st: st["status"] in ("COMPLETE", "FAILED", "UNSUPPORTED_IMAGE"),
        timeout_s=120.0,
        interval_s=5.0,
    )
    scan_status = scan_result["status"]
    assert scan_status in ("FAILED", "UNSUPPORTED_IMAGE"), (
        f"an OS-less image must not scan COMPLETE; scan status {scan_status!r}: {scan_result!r}"
    )
    assert "unsupported" in scan_result.get("description", "").lower(), scan_result

    # --- observe replication status for the image pushed under the now-active rule ---
    # Wait for the destination's entry to reach a terminal state (not merely "present") --
    # an entry can exist while still IN_PROGRESS, and that must not be mistaken for the
    # replication having actually completed.
    statuses = _poll_until(
        lambda: ecr.describe_image_replication_status(
            repositoryName=repo_name, imageId={"imageDigest": digest}
        )["replicationStatuses"],
        lambda statuses: any(
            s["region"] == dest_region and s["status"] in ("COMPLETE", "FAILED")
            for s in statuses
        ),
        timeout_s=180.0,
        interval_s=10.0,
    )
    matching = [s for s in statuses if s["region"] == dest_region]
    assert matching, f"expected a replication status entry for {dest_region}, got {statuses}"
    assert all(s["status"] == "COMPLETE" for s in matching), (
        f"replication to {dest_region} did not complete: {matching}"
    )

    # --- force delete and confirm gone ---
    ecr.delete_repository(repositoryName=repo_name, force=True)
    repo_deleted["done"] = True
    code, message = _error(lambda: ecr.describe_repositories(repositoryNames=[repo_name]))
    assert code == "RepositoryNotFoundException", code
    expected = f"The repository with name '{repo_name}' does not exist in the registry with id '{ctx.account}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _empty_gzip_tar_blob() -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz"):
        pass
    return buf.getvalue()


def _push_minimal_image(ecr, repo_name: str, tag: str) -> str:
    layer_bytes = _empty_gzip_tar_blob()
    layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
    config_obj = {
        "architecture": "amd64",
        "os": "linux",
        "config": {"Labels": {"sim2real-nonce": str(uuid.uuid4())}},
        "rootfs": {"type": "layers", "diff_ids": [layer_digest]},
    }
    config_bytes = json.dumps(config_obj).encode("utf-8")
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()

    for blob, digest in ((config_bytes, config_digest), (layer_bytes, layer_digest)):
        upload_id = ecr.initiate_layer_upload(repositoryName=repo_name)["uploadId"]
        ecr.upload_layer_part(
            repositoryName=repo_name,
            uploadId=upload_id,
            partFirstByte=0,
            partLastByte=len(blob) - 1,
            layerPartBlob=blob,
        )
        try:
            ecr.complete_layer_upload(
                repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest]
            )
        except ecr.exceptions.LayerAlreadyExistsException:
            pass

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
    put_response = ecr.put_image(
        repositoryName=repo_name,
        imageManifest=json.dumps(manifest),
        imageTag=tag,
    )
    return put_response["image"]["imageId"]["imageDigest"]


def _poll_until(probe, predicate, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition never satisfied within {timeout_s}s, last value={value!r}"
            )
        time.sleep(interval_s)
        value = probe()
    return value


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
