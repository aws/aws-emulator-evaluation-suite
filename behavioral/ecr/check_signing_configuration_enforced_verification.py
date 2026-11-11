"""signing-configuration-enforced-verification."""
from __future__ import annotations

import gzip
import hashlib
import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "signing-configuration-enforced-verification"
GROUP = "server-side"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:ecr-signing-configuration")
def run(ctx) -> None:
    """A registry signing rule naming a nonexistent Signer profile makes DescribeImageSigningStatus
    report FAILED for a newly pushed image, with a failureReason naming that profile."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    repo_name = ctx.unique_name("sim2real-ecr-signing-")
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    original = None
    try:
        original = ecr.get_signing_configuration()["signingConfiguration"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "SigningConfigurationNotFoundException":
            raise

    def _restore():
        if original is None:
            try:
                ecr.delete_signing_configuration()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "SigningConfigurationNotFoundException":
                    raise
        else:
            ecr.put_signing_configuration(signingConfiguration=original)

    ctx.on_cleanup(_restore)

    # A well-formed but nonexistent Signer profile ARN, so ECR's signing job for the image fails.
    profile_name = "Sim2RealNoSuchProfile_" + uuid.uuid4().hex
    profile_arn = f"arn:aws:signer:{ctx.region}:{account_id}:/signing-profiles/{profile_name}"

    ecr.put_signing_configuration(signingConfiguration={
        "rules": [{
            "signingProfileArn": profile_arn,
            "repositoryFilters": [{"filter": f"{repo_name}*", "filterType": "WILDCARD_MATCH"}],
        }],
    })

    digest, _manifest = _push_test_image(ecr, repo_name, "v1", seed=b"signing-payload")

    def _probe():
        resp = ecr.describe_image_signing_status(repositoryName=repo_name, imageId={"imageDigest": digest})
        statuses = resp.get("signingStatuses", [])
        if not statuses:
            return None
        if any(s["status"] == "IN_PROGRESS" for s in statuses):
            return None
        return statuses

    statuses = _poll_until(_probe, lambda s: s is not None, timeout_s=180.0, interval_s=5.0)
    assert len(statuses) == 1, f"expected exactly one signing status entry, got {statuses!r}"
    entry = statuses[0]
    assert entry["signingProfileArn"] == profile_arn, (
        f"expected signingProfileArn {profile_arn!r}, got {entry['signingProfileArn']!r}"
    )
    assert entry["status"] == "FAILED", f"expected status FAILED, got {entry['status']!r}: {entry!r}"
    assert entry.get("failureReason"), f"expected a non-empty failureReason on FAILED, got {entry!r}"
    assert profile_name in entry["failureReason"], (
        f"expected failureReason to name the missing profile {profile_name!r}, got {entry['failureReason']!r}"
    )



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
