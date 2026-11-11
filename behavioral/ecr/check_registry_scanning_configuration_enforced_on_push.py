"""registry-scanning-configuration-enforced-on-push."""
from __future__ import annotations

import gzip
import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "registry-scanning-configuration-enforced-on-push"
GROUP = "server-side"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:ecr-registry-scanning")
def run(ctx) -> None:
    """Enabling scan-on-push at the registry level via PutRegistryScanningConfiguration
    causes a newly pushed image to be scanned automatically, without ever calling
    StartImageScan -- DescribeImageScanFindings reaches a terminal scan status on its own."""
    ecr = ctx.client("ecr")
    repo_name = ctx.unique_name("sim2real-ecr-scanpush-")
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    original = ecr.get_registry_scanning_configuration()["scanningConfiguration"]

    def _restore():
        ecr.put_registry_scanning_configuration(
            scanType=original["scanType"], rules=original.get("rules", [])
        )

    ctx.on_cleanup(_restore)

    ecr.put_registry_scanning_configuration(
        scanType="BASIC",
        rules=[{
            "scanFrequency": "SCAN_ON_PUSH",
            "repositoryFilters": [{"filter": f"{repo_name}*", "filterType": "WILDCARD"}],
        }],
    )

    # independent read confirming the mutation actually took effect, not just accepted
    applied = ecr.get_registry_scanning_configuration()["scanningConfiguration"]
    assert applied["scanType"] == "BASIC", f"expected BASIC, got {applied['scanType']!r}"
    applied_rules = applied["rules"]
    assert len(applied_rules) == 1, f"expected exactly 1 rule, got {len(applied_rules)}"
    assert applied_rules[0]["scanFrequency"] == "SCAN_ON_PUSH", (
        f"expected SCAN_ON_PUSH, got {applied_rules[0]['scanFrequency']!r}"
    )
    assert applied_rules[0]["repositoryFilters"][0]["filter"] == f"{repo_name}*", (
        f"expected filter {repo_name}*, got {applied_rules[0]['repositoryFilters'][0]['filter']!r}"
    )

    digest, _manifest = _push_test_image(ecr, repo_name, "v1", seed=b"scan-on-push-payload")

    terminal = {"COMPLETE", "FAILED", "UNSUPPORTED_IMAGE"}

    def _probe():
        try:
            resp = ecr.describe_image_scan_findings(
                repositoryName=repo_name, imageId={"imageDigest": digest}
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ScanNotFoundException":
                return None
            raise
        return resp["imageScanStatus"]["status"]

    status = _poll_until(_probe, lambda s: s in terminal, timeout_s=180.0, interval_s=5.0)
    assert status in terminal, f"unexpected terminal scan status: {status}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


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
