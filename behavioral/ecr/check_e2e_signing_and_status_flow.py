"""e2e-signing-and-status-flow."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "e2e-signing-and-status-flow"
GROUP = "e2e"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:ecr-signing-configuration")
def run(ctx) -> None:
    """A managed-signing rule records a signing attempt for a matching pushed image, leaves a
    non-matching repository untouched, and GetSigningConfiguration reports none after deletion."""
    ecr = ctx.client("ecr")

    profile_arn = _create_signing_profile(ctx)
    matching_repo = _create_repo(ctx)
    other_repo = _create_repo(ctx)

    # baseline: before any signing configuration exists, freshly pushed images have no
    # signing statuses and GetSigningConfiguration reports none configured
    baseline = _push_image(ctx, matching_repo["repositoryName"], tag="baseline")
    baseline_status = ecr.describe_image_signing_status(
        repositoryName=matching_repo["repositoryName"],
        imageId={"imageDigest": baseline["imageId"]["imageDigest"]},
    )
    assert baseline_status["signingStatuses"] == [], (
        f"expected no signing statuses before any signing configuration exists, "
        f"got {baseline_status['signingStatuses']!r}"
    )
    baseline_code, baseline_message = _error(ecr.get_signing_configuration)
    assert baseline_code == "SigningConfigurationNotFoundException", (
        f"expected SigningConfigurationNotFoundException before any PutSigningConfiguration, "
        f"got {baseline_code!r}"
    )
    expected = f"The signing configuration does not exist in the registry with id '{ctx.account}'"
    assert baseline_message == expected, f"expected message {expected!r}, got {baseline_message!r}"

    ecr.put_signing_configuration(
        signingConfiguration={
            "rules": [
                {
                    "signingProfileArn": profile_arn,
                    "repositoryFilters": [
                        {"filter": matching_repo["repositoryName"], "filterType": "WILDCARD_MATCH"}
                    ],
                }
            ]
        }
    )
    ctx.on_cleanup(lambda: _delete_signing_configuration(ecr))

    put_config = ecr.get_signing_configuration()["signingConfiguration"]
    assert put_config["rules"][0]["signingProfileArn"] == profile_arn, (
        f"expected the rule just written to name {profile_arn!r}, "
        f"got {put_config['rules'][0].get('signingProfileArn')!r}"
    )

    matched = _push_image(ctx, matching_repo["repositoryName"], tag="matched")
    unmatched = _push_image(ctx, other_repo["repositoryName"], tag="unmatched")

    matched_status = _poll_until(
        lambda: ecr.describe_image_signing_status(
            repositoryName=matching_repo["repositoryName"],
            imageId={"imageDigest": matched["imageId"]["imageDigest"]},
        ),
        lambda resp: any(s["status"] in ("COMPLETE", "FAILED") for s in resp["signingStatuses"]),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert len(matched_status["signingStatuses"]) == 1, (
        f"expected exactly one signing status entry for the matched image, "
        f"got {matched_status['signingStatuses']!r}"
    )
    entry = matched_status["signingStatuses"][0]
    assert entry["signingProfileArn"] == profile_arn, (
        f"expected the recorded attempt to name {profile_arn!r}, got {entry.get('signingProfileArn')!r}"
    )
    assert entry["status"] == "COMPLETE", (
        f"expected the real AWS Signer job to complete, got status={entry['status']!r} "
        f"failureCode={entry.get('failureCode')!r} failureReason={entry.get('failureReason')!r}"
    )

    # a repository that doesn't match any signing rule never gets a signing attempt recorded
    unmatched_status = ecr.describe_image_signing_status(
        repositoryName=other_repo["repositoryName"], imageId={"imageDigest": unmatched["imageId"]["imageDigest"]}
    )
    assert unmatched_status["signingStatuses"] == [], (
        f"expected no signing attempt for a repository outside the signing rule's filter, "
        f"got {unmatched_status['signingStatuses']!r}"
    )

    ecr.delete_signing_configuration()
    post_delete_code, post_delete_message = _error(ecr.get_signing_configuration)
    assert post_delete_code == "SigningConfigurationNotFoundException", (
        f"expected SigningConfigurationNotFoundException after DeleteSigningConfiguration, "
        f"got {post_delete_code!r}"
    )
    assert post_delete_message == expected, (
        f"expected message {expected!r}, got {post_delete_message!r}"
    )


import hashlib
import json


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


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _create_signing_profile(ctx):
    signer = ctx.client("signer")
    name = ctx.unique_name("s2r_ecr_sign_").replace("-", "_")
    resp = signer.put_signing_profile(
        profileName=name, platformId="Notation-OCI-SHA384-ECDSA", tags={"sim2real": CHECK}
    )
    ctx.on_cleanup(lambda: signer.cancel_signing_profile(profileName=name))
    return resp["arn"]


def _create_repo(ctx, **kwargs):
    ecr = ctx.client("ecr")
    name = ctx.unique_name("sim2real-ecr-sign-")
    resp = ecr.create_repository(repositoryName=name, tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs)
    ctx.on_cleanup(lambda: ecr.delete_repository(repositoryName=name, force=True))
    return resp["repository"]


def _delete_signing_configuration(ecr):
    from botocore.exceptions import ClientError

    try:
        ecr.delete_signing_configuration()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "SigningConfigurationNotFoundException":
            raise


_MANIFEST_MEDIA_TYPE = "application/vnd.docker.distribution.manifest.v2+json"
_CONFIG_MEDIA_TYPE = "application/vnd.docker.container.image.v1+json"
_LAYER_MEDIA_TYPE = "application/vnd.docker.image.rootfs.diff.tar.gzip"


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
