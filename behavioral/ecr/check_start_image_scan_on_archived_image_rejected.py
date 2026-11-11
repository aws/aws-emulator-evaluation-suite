"""start-image-scan-on-archived-image-rejected."""
from __future__ import annotations

import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-image-scan-on-archived-image-rejected"
GROUP = "error-semantics"
SERVICES = ["ecr"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:control", "plane:data", "resource:account-singleton:ecr-registry-scanning")
def run(ctx) -> None:
    """StartImageScan on an image archived via UpdateImageStorageClass raises
    ImageArchivedException instead of queuing a scan, while scanning a sibling active
    image in the same repository succeeds and runs to a terminal scan status."""
    ecr = ctx.client("ecr")
    _ensure_basic_scanning_enabled(ctx, ecr)
    repo = _create_repo(ctx, ecr)

    archived_image = _push_minimal_image(ecr, repo, "archived-target")
    ecr.update_image_storage_class(
        repositoryName=repo,
        imageId={"imageDigest": archived_image["digest"]},
        targetStorageClass="ARCHIVE",
    )
    _poll_until(
        lambda: _image_status(ecr, repo, archived_image["digest"]),
        lambda status: status == "ARCHIVED",
        timeout_s=60.0,
    )

    code, message = _client_error(
        lambda: ecr.start_image_scan(
            repositoryName=repo, imageId={"imageDigest": archived_image["digest"]}
        )
    )
    assert code == "ImageArchivedException", f"expected ImageArchivedException, got {code!r}"
    assert message == (
        f"The image with imageId {{imageDigest:'{archived_image['digest']}', imageTag:'null'}} is "
        f"archived within the repository with name '{repo}' in the registry with id "
        f"'{ctx.account}'"
    ), message

    # Effect-absent: no scan was ever queued for the archived image.
    findings_code, findings_message = _client_error(
        lambda: ecr.describe_image_scan_findings(
            repositoryName=repo, imageId={"imageDigest": archived_image["digest"]}
        )
    )
    assert findings_code == "ScanNotFoundException", (
        f"expected ScanNotFoundException, got {findings_code!r}"
    )
    assert findings_message == (
        f"Image scan does not exist for the image with '{{imageDigest:'{archived_image['digest']}', "
        f"imageTag:'null'}}' in the repository with name '{repo}' in the registry with id "
        f"'{ctx.account}'"
    ), findings_message

    # Positive control: a non-archived sibling image can be scanned to completion.
    active_image = _push_minimal_image(ecr, repo, "active-sibling")
    start_resp = ecr.start_image_scan(
        repositoryName=repo, imageId={"imageDigest": active_image["digest"]}
    )
    active_start_status = start_resp["imageScanStatus"]["status"]
    assert active_start_status in ("PENDING", "IN_PROGRESS", "COMPLETE"), (
        f"expected the active sibling's scan to start, got status {active_start_status!r}"
    )

    terminal = _poll_until(
        lambda: ecr.describe_image_scan_findings(
            repositoryName=repo, imageId={"imageDigest": active_image["digest"]}
        )["imageScanStatus"]["status"],
        lambda status: status
        in ("COMPLETE", "FAILED", "UNSUPPORTED_IMAGE", "FINDINGS_UNAVAILABLE"),
        timeout_s=120.0,
    )
    assert terminal in ("COMPLETE", "FAILED", "UNSUPPORTED_IMAGE", "FINDINGS_UNAVAILABLE"), (
        f"expected the active sibling's scan to reach a terminal status, got {terminal!r}"
    )


def _client_error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value={value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


def _create_repo(ctx, ecr) -> str:
    name = ctx.unique_name("sim2real-ecr-behav-")
    ecr.create_repository(
        repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _delete_repo_force(ecr, name))
    return name


def _ensure_basic_scanning_enabled(ctx, ecr) -> None:
    """StartImageScan raises ValidationException ("This feature is disabled") if
    the registry's scanning configuration doesn't have basic scanning enabled for
    the repository. Force BASIC/MANUAL scanning on for all repos for the duration
    of this check, then restore whatever configuration was there before."""
    original = ecr.get_registry_scanning_configuration()["scanningConfiguration"]

    def _restore():
        ecr.put_registry_scanning_configuration(
            scanType=original.get("scanType", "BASIC"),
            rules=original.get("rules", []),
        )

    ctx.on_cleanup(_restore)
    # Empty rules => BASIC scanning capability is enabled registry-wide but no
    # repository auto-scans on push, so our explicit StartImageScan calls are the
    # only scans triggered (avoids racing/consuming the once-per-24h scan quota).
    ecr.put_registry_scanning_configuration(scanType="BASIC", rules=[])



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
            # Vary the config blob per tag so each image gets its own unique
            # layer digest -- reusing a digest that already exists in the
            # repo makes CompleteLayerUpload raise LayerAlreadyExistsException.
            "sim2real_tag_nonce": tag,
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


def _image_status(ecr, repo_name: str, digest: str) -> str:
    resp = ecr.describe_images(repositoryName=repo_name, imageIds=[{"imageDigest": digest}])
    return resp["imageDetails"][0]["imageStatus"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
