"""e2e-image-scan-lifecycle."""
from __future__ import annotations

import gzip
import hashlib
import io
import json
import tarfile
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-image-scan-lifecycle"
GROUP = "e2e"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """StartImageScan starts a scan that DescribeImageScanFindings, polled, reports COMPLETE with
    an imageScanCompletedAt and a findingSeverityCounts map."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-scan-")
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    tag = "scan-target"
    _push_minimal_image(ecr, repo_name, tag)
    image_id = {"imageTag": tag}

    start_resp = ecr.start_image_scan(repositoryName=repo_name, imageId=image_id)
    start_status = start_resp["imageScanStatus"]["status"]
    assert start_status in ("PENDING", "IN_PROGRESS", "COMPLETE"), (
        f"expected StartImageScan status in (PENDING, IN_PROGRESS, COMPLETE), got {start_status!r}"
    )

    terminal = {"COMPLETE", "FAILED", "UNSUPPORTED_IMAGE"}
    last_status = None
    findings_resp = None
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            findings_resp = ecr.describe_image_scan_findings(repositoryName=repo_name, imageId=image_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ScanNotFoundException":
                time.sleep(5)
                continue
            raise
        last_status = findings_resp["imageScanStatus"]["status"]
        if last_status in terminal:
            break
        time.sleep(2)

    assert last_status == "COMPLETE", f"scan never reached COMPLETE (last status={last_status!r})"
    findings = findings_resp["imageScanFindings"]
    assert "findingSeverityCounts" in findings, (
        f"expected findingSeverityCounts on a COMPLETEd scan, got keys {sorted(findings)}"
    )
    assert isinstance(findings["findingSeverityCounts"], dict), (
        f"expected findingSeverityCounts to be a dict, got {findings['findingSeverityCounts']!r}"
    )
    assert "imageScanCompletedAt" in findings, (
        f"expected imageScanCompletedAt on a COMPLETEd scan, got keys {sorted(findings)}"
    )


def _push_minimal_image(ecr, repository_name: str, tag: str) -> str:
    """Push a minimal, syntactically valid single-layer Docker v2 image via the raw
    layer-upload + PutImage API (no docker daemon needed) and return its digest.

    The layer contains a recognizable /etc/os-release (Alpine) plus an (empty) apk
    package database so ECR's basic image-scanning engine (Clair) can identify an
    OS and actually run a scan to COMPLETE rather than reporting UNSUPPORTED_IMAGE
    for a from-scratch, OS-less layer."""
    layer_tar = _make_os_layer_tar()
    layer_bytes = gzip.compress(layer_tar, mtime=0)
    layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
    diff_id = "sha256:" + hashlib.sha256(layer_tar).hexdigest()
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": [diff_id]},
        "history": [],
    }
    config_bytes = json.dumps(config).encode()
    config_digest = "sha256:" + hashlib.sha256(config_bytes).hexdigest()

    for blob, digest in ((layer_bytes, layer_digest), (config_bytes, config_digest)):
        upload_id = ecr.initiate_layer_upload(repositoryName=repository_name)["uploadId"]
        ecr.upload_layer_part(
            repositoryName=repository_name,
            uploadId=upload_id,
            partFirstByte=0,
            partLastByte=len(blob) - 1,
            layerPartBlob=blob,
        )
        ecr.complete_layer_upload(repositoryName=repository_name, uploadId=upload_id, layerDigests=[digest])

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
    resp = ecr.put_image(
        repositoryName=repository_name,
        imageManifest=json.dumps(manifest),
        imageManifestMediaType=manifest["mediaType"],
        imageTag=tag,
    )
    return resp["image"]["imageId"]["imageDigest"]


def _make_os_layer_tar() -> bytes:
    """Build an uncompressed tar containing an Alpine /etc/os-release and an empty
    apk installed-package database, so the scan engine detects a real (if
    package-less) OS rather than treating the image as unsupported/from-scratch."""
    buf = io.BytesIO()
    tar = tarfile.TarFile(fileobj=buf, mode="w")

    os_release = (
        b'NAME="Alpine Linux"\nID=alpine\nVERSION_ID=3.18.4\n'
        b'PRETTY_NAME="Alpine Linux v3.18"\nHOME_URL="https://alpinelinux.org/"\n'
    )
    info = tarfile.TarInfo(name="etc/os-release")
    info.size = len(os_release)
    tar.addfile(info, io.BytesIO(os_release))

    installed_db = b""
    info2 = tarfile.TarInfo(name="lib/apk/db/installed")
    info2.size = len(installed_db)
    tar.addfile(info2, io.BytesIO(installed_db))

    tar.close()
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

