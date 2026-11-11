"""update-shape-validation-precedes-jit-gate-for-bucket-name."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-shape-validation-precedes-jit-gate-for-bucket-name"
GROUP = "overly-permissive"
SERVICES = ["ssm-guiconnect"]

_JIT_DENIED = "Just-in-time node access is not enabled. You must set up just-in-time node access to record RDP connections."
_BAD_BUCKET_NAME = "The value provided for ConnectionRecordingPreferences.RecordingDestinations.S3Buckets.BucketName isn't valid."
_NOT_FOUND = "The following  resource cannot be found: 'ConnectionRecordingPreferences'"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An IP-address-shaped BucketName is rejected with ValidationException ahead of the
    account-level just-in-time gate, which denies the same call with a well-shaped bucket name
    with AccessDeniedException."""
    guiconnect = ctx.client("ssm-guiconnect")
    account = _account_id(ctx)
    bucket = _create_recording_bucket(ctx)
    key_arn = _create_kms_key(ctx)

    control_code, control_message = _error(
        lambda: guiconnect.update_connection_recording_preferences(
            ConnectionRecordingPreferences=_prefs(bucket, account, key_arn),
            ClientToken=ctx.unique_name("ctl-")[:64],
        )
    )
    assert control_code == "AccessDeniedException", (
        f"expected a well-shaped request to reach and be denied by the JIT gate, got {control_code}"
    )
    assert control_message == _JIT_DENIED, f"unexpected AccessDeniedException message: {control_message!r}"

    bad_code, bad_message = _error(
        lambda: guiconnect.update_connection_recording_preferences(
            ConnectionRecordingPreferences=_prefs("192.168.1.1", account, key_arn),
            ClientToken=ctx.unique_name("bad-")[:64],
        )
    )
    assert bad_code == "ValidationException", (
        f"expected ValidationException for a malformed bucket name, got {bad_code}"
    )
    assert bad_message == _BAD_BUCKET_NAME, f"unexpected ValidationException message: {bad_message!r}"

    after_code, after_message = _error(lambda: guiconnect.get_connection_recording_preferences())
    assert after_code == "ResourceNotFoundException", (
        f"neither the JIT-denied nor the malformed update should have created state, but Get returned {after_code}"
    )
    assert after_message == _NOT_FOUND, f"unexpected ResourceNotFoundException message: {after_message!r}"


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


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


def _create_recording_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-guic-")
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup() -> None:
        try:
            s3.delete_bucket(Bucket=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return name


def _prefs(bucket_name: str, bucket_owner: str, kms_arn: str) -> dict[str, Any]:
    return {
        "RecordingDestinations": {"S3Buckets": [{"BucketName": bucket_name, "BucketOwner": bucket_owner}]},
        "KMSKeyArn": kms_arn,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
