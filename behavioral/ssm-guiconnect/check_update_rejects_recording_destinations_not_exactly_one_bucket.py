"""update-rejects-recording-destinations-not-exactly-one-bucket."""
from __future__ import annotations

from typing import Any

from botocore.config import Config

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-rejects-recording-destinations-not-exactly-one-bucket"
GROUP = "overly-permissive"
SERVICES = ["ssm-guiconnect"]

_ZERO_BUCKETS = "ConnectionRecordingPreferences.RecordingDestinations.S3Buckets must contain at least 1 value."
_TWO_BUCKETS = "ConnectionRecordingPreferences.RecordingDestinations.S3Buckets cannot contain more than 1 value."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """With client-side validation off, Update with RecordingDestinations.S3Buckets of zero or two
    entries is rejected with ValidationException at the service, ahead of the account-level
    just-in-time gate."""
    guiconnect = ctx.client("ssm-guiconnect")
    account = _account_id(ctx)
    bucket_a = _create_recording_bucket(ctx)
    bucket_b = _create_recording_bucket(ctx)
    key_arn = _create_kms_key(ctx)

    empty_prefs = {"RecordingDestinations": {"S3Buckets": []}, "KMSKeyArn": key_arn}
    # botocore fixes parameter validation at client construction, so the unvalidated client is a
    # separate ctx client on the same target and identity.
    unvalidated = ctx.client("ssm-guiconnect", config=Config(parameter_validation=False))
    code_empty, message_empty = _error(
        lambda: unvalidated.update_connection_recording_preferences(
            ConnectionRecordingPreferences=empty_prefs, ClientToken=ctx.unique_name("empty-")[:64]
        )
    )
    assert code_empty == "ValidationException", (
        f"expected the service itself to reject zero buckets with ValidationException, got {code_empty}"
    )
    assert message_empty == _ZERO_BUCKETS, f"unexpected ValidationException message: {message_empty!r}"

    two_prefs = {
        "RecordingDestinations": {
            "S3Buckets": [
                {"BucketName": bucket_a, "BucketOwner": account},
                {"BucketName": bucket_b, "BucketOwner": account},
            ]
        },
        "KMSKeyArn": key_arn,
    }
    code_two, message_two = _error(
        lambda: guiconnect.update_connection_recording_preferences(
            ConnectionRecordingPreferences=two_prefs, ClientToken=ctx.unique_name("two-")[:64]
        )
    )
    assert code_two == "ValidationException", f"expected ValidationException for two buckets, got {code_two}"
    assert message_two == _TWO_BUCKETS, f"unexpected ValidationException message: {message_two!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
