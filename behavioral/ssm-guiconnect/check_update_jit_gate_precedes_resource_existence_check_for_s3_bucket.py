"""update-jit-gate-precedes-resource-existence-check-for-s3-bucket."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "update-jit-gate-precedes-resource-existence-check-for-s3-bucket"
GROUP = "error-semantics"
SERVICES = ["ssm-guiconnect"]

_JIT_DENIED = "Just-in-time node access is not enabled. You must set up just-in-time node access to record RDP connections."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Update pointing at a well-formed but nonexistent S3 bucket name is still denied by the
    account-level just-in-time gate before any bucket-existence lookup would occur."""
    guiconnect = ctx.client("ssm-guiconnect")
    account = _account_id(ctx)
    key_arn = _create_kms_key(ctx)
    missing_bucket = ctx.unique_name("sim2real-guic-missing-")

    error = _client_error(
        lambda: guiconnect.update_connection_recording_preferences(
            ConnectionRecordingPreferences=_prefs(missing_bucket, account, key_arn),
            ClientToken=ctx.unique_name("bad-")[:64],
        )
    )
    code = error.get("Code")
    assert code == "AccessDeniedException", f"expected the JIT gate to deny first, got {code}"
    message = error.get("Message", "")
    assert message == _JIT_DENIED, (
        f"expected the just-in-time-node-access gate message (proving the gate, not a bucket "
        f"existence lookup or an unrelated permission denial, produced this refusal), got: {message!r}"
    )


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(
        f"expected the JIT gate to deny the call, but it SUCCEEDED and returned {result!r}"
    )


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _create_kms_key(ctx) -> str:
    kms = ctx.client("kms")
    resp = kms.create_key(
        Description="sim2real-behav-ssmguiconnect",
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "SystemsManagerJustInTimeNodeAccessManaged", "TagValue": "true"}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    arn = resp["KeyMetadata"]["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    return arn


def _prefs(bucket_name: str, bucket_owner: str, kms_arn: str) -> dict[str, Any]:
    return {
        "RecordingDestinations": {"S3Buckets": [{"BucketName": bucket_name, "BucketOwner": bucket_owner}]},
        "KMSKeyArn": kms_arn,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
