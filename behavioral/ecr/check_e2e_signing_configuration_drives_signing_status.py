"""e2e-signing-configuration-drives-signing-status."""
from __future__ import annotations

import gzip
import hashlib
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-signing-configuration-drives-signing-status"
GROUP = "e2e"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "resource:account-singleton:ecr-signing-configuration")
def run(ctx) -> None:
    """A PutSigningConfiguration rule for a repository makes a pushed image's
    DescribeImageSigningStatus show one COMPLETE AWS Signer job for that signing profile."""
    ecr = ctx.client("ecr")
    signer = ctx.client("signer")

    profile_name = ctx.unique_name("sim2real_ecr_sig_").replace("-", "_")
    profile = signer.put_signing_profile(
        profileName=profile_name,
        platformId="Notation-OCI-SHA384-ECDSA",
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: signer.cancel_signing_profile(profileName=profile_name))
    profile_arn = profile["arn"]

    repo_name = ctx.unique_name("sim2real-ecr-sig-repo-")
    ecr.create_repository(repositoryName=repo_name, tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=repo_name, force=True))

    original_config, had_config = _get_signing_configuration(ecr)

    def _restore():
        if had_config:
            ecr.put_signing_configuration(signingConfiguration=original_config)
        else:
            try:
                ecr.delete_signing_configuration()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "SigningConfigurationNotFoundException":
                    raise

    ctx.on_cleanup(_restore)

    rule = {
        "signingProfileArn": profile_arn,
        "repositoryFilters": [{"filter": repo_name, "filterType": "WILDCARD_MATCH"}],
    }
    ecr.put_signing_configuration(signingConfiguration={"rules": [rule]})

    tag = "sign-target"
    _push_minimal_image(ecr, repo_name, tag)
    image_id = {"imageTag": tag}

    terminal = {"COMPLETE", "FAILED"}
    statuses: list = []
    deadline = time.monotonic() + 240
    while time.monotonic() < deadline:
        resp = ecr.describe_image_signing_status(repositoryName=repo_name, imageId=image_id)
        statuses = resp["signingStatuses"]
        if statuses and all(s["status"] in terminal for s in statuses):
            break
        time.sleep(2)

    assert len(statuses) == 1, f"expected exactly one signing status entry, got {statuses!r}"
    assert statuses[0]["signingProfileArn"] == profile_arn, (
        f"expected signingProfileArn {profile_arn!r}, got {statuses[0]['signingProfileArn']!r}"
    )
    assert statuses[0]["status"] == "COMPLETE", f"signing did not complete: {statuses[0]!r}"


def _get_signing_configuration(ecr):
    try:
        return ecr.get_signing_configuration()["signingConfiguration"], True
    except ClientError as e:
        if e.response["Error"]["Code"] == "SigningConfigurationNotFoundException":
            return None, False
        raise


def _push_minimal_image(ecr, repository_name: str, tag: str) -> str:
    layer_bytes = gzip.compress(b"", mtime=0)
    layer_digest = "sha256:" + hashlib.sha256(layer_bytes).hexdigest()
    config = {
        "architecture": "amd64",
        "os": "linux",
        "config": {},
        "rootfs": {"type": "layers", "diff_ids": ["sha256:" + hashlib.sha256(b"").hexdigest()]},
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
