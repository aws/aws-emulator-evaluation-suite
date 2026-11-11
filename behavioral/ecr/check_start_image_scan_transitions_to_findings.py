"""start-image-scan-transitions-to-findings."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time

from behavioral_harness import tags

CHECK = "start-image-scan-transitions-to-findings"
GROUP = "state-machine"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:ecr-registry-scanning")
def run(ctx) -> None:
    """StartImageScan moves a freshly pushed image out of "no scan" state, and
    DescribeImageScanFindings eventually reports COMPLETE with real findings
    metadata -- not just an accepted status field on the StartImageScan response."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-imgscan-")
    ecr.create_repository(repositoryName=repo_name, imageScanningConfiguration={"scanOnPush": False})
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))
    _enable_basic_scanning(ctx, ecr)

    digest = _push_minimal_image(ecr, repo_name, "v1", ctx.unique_name("m"))
    image_id = {"imageDigest": digest}

    start_resp = ecr.start_image_scan(repositoryName=repo_name, imageId=image_id)
    assert start_resp["imageScanStatus"]["status"] in ("PENDING", "IN_PROGRESS"), (
        f"expected PENDING/IN_PROGRESS right after StartImageScan, got {start_resp['imageScanStatus']}"
    )

    # A from-scratch, OS-less layer leaves the basic scanner (Clair) stuck in
    # IN_PROGRESS well past any reasonable poll budget. _push_minimal_image
    # embeds a recognizable (if package-less) Alpine OS so the scanner can reach a
    # real terminal verdict instead of hanging.
    terminal_statuses = {
        "COMPLETE",
        "FAILED",
        "UNSUPPORTED_IMAGE",
        "FINDINGS_UNAVAILABLE",
        "SCAN_ELIGIBILITY_EXPIRED",
        "LIMIT_EXCEEDED",
        "IMAGE_ARCHIVED",
    }

    def probe():
        return ecr.describe_image_scan_findings(repositoryName=repo_name, imageId=image_id)

    def done(resp):
        return resp["imageScanStatus"]["status"] in terminal_statuses

    result = _poll_until(probe, done, timeout_s=180, interval_s=5)
    status = result["imageScanStatus"]["status"]
    assert status == "COMPLETE", f"expected the scan to reach COMPLETE, got {status!r}: {result}"
    assert result["repositoryName"] == repo_name, (
        f"expected repositoryName {repo_name!r} on the terminal read, got {result['repositoryName']!r}"
    )
    assert result["imageId"]["imageDigest"] == digest, (
        f"expected imageDigest {digest!r} on the terminal read, got {result['imageId']['imageDigest']!r}"
    )
    findings = result["imageScanFindings"]
    assert "findingSeverityCounts" in findings, f"expected findingSeverityCounts on a COMPLETE scan: {findings}"
    assert "imageScanCompletedAt" in findings, f"expected imageScanCompletedAt on a COMPLETE scan: {findings}"


def _enable_basic_scanning(ctx, ecr) -> None:
    """StartImageScan needs BASIC scanning enabled on the registry, an account-wide
    singleton: capture the original configuration, restore it in cleanup, then set
    BASIC with no rules so only the explicit StartImageScan triggers a scan."""
    original = ecr.get_registry_scanning_configuration()["scanningConfiguration"]

    def _restore():
        ecr.put_registry_scanning_configuration(
            scanType=original["scanType"], rules=original.get("rules", [])
        )

    ctx.on_cleanup(_restore)
    ecr.put_registry_scanning_configuration(scanType="BASIC", rules=[])


def _poll_until(probe, predicate, timeout_s=180.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met before timeout; last result: {last}")


def _build_layer_and_config(marker: str):
    # /etc/os-release plus an (empty) apk package database gives ECR's basic
    # scanner (Clair) a recognizable OS to identify, so it can actually run a scan
    # to COMPLETE instead of hanging (or eventually reporting UNSUPPORTED_IMAGE for
    # a from-scratch, OS-less layer).
    os_release = (
        b'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.18.4\n'
        b'PRETTY_NAME="Alpine Linux v3.18"\nHOME_URL="https://alpinelinux.org/"\n'
    )
    marker_payload = f"sim2real-behav-{marker}".encode("utf-8")
    tar_buf = io.BytesIO()
    with tarfile.open(fileobj=tar_buf, mode="w") as tar:
        info = tarfile.TarInfo(name="etc/os-release")
        info.size = len(os_release)
        tar.addfile(info, io.BytesIO(os_release))
        info2 = tarfile.TarInfo(name="lib/apk/db/installed")
        info2.size = 0
        tar.addfile(info2, io.BytesIO(b""))
        info3 = tarfile.TarInfo(name="marker.txt")
        info3.size = len(marker_payload)
        tar.addfile(info3, io.BytesIO(marker_payload))
    tar_bytes = tar_buf.getvalue()
    gz_bytes = gzip.compress(tar_bytes, compresslevel=6)
    diff_id = "sha256:" + hashlib.sha256(tar_bytes).hexdigest()
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        "comment": f"sim2real-behav-{marker}",
    }
    config_bytes = json.dumps(config).encode("utf-8")
    return gz_bytes, config_bytes


def _upload_blob(ecr, repo_name: str, data: bytes) -> tuple[str, int]:
    digest = "sha256:" + hashlib.sha256(data).hexdigest()
    init = ecr.initiate_layer_upload(repositoryName=repo_name)
    upload_id = init["uploadId"]
    ecr.upload_layer_part(
        repositoryName=repo_name,
        uploadId=upload_id,
        partFirstByte=0,
        partLastByte=len(data) - 1,
        layerPartBlob=data,
    )
    ecr.complete_layer_upload(repositoryName=repo_name, uploadId=upload_id, layerDigests=[digest])
    return digest, len(data)


def _push_minimal_image(ecr, repo_name: str, tag: str, marker: str) -> str:
    gz_bytes, config_bytes = _build_layer_and_config(marker)
    config_digest, config_size = _upload_blob(ecr, repo_name, config_bytes)
    layer_digest, layer_size = _upload_blob(ecr, repo_name, gz_bytes)
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
    manifest_str = json.dumps(manifest)
    resp = ecr.put_image(repositoryName=repo_name, imageManifest=manifest_str, imageTag=tag)
    return resp["image"]["imageId"]["imageDigest"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
