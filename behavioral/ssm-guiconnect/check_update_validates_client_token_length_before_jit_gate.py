"""update-validates-client-token-length-before-jit-gate."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-validates-client-token-length-before-jit-gate"
GROUP = "error-semantics"
SERVICES = ["ssm-guiconnect"]

_TOKEN_TOO_LONG = "The length for ClientToken cannot be greater than 64."
_JIT_DENIED = "Just-in-time node access is not enabled. You must set up just-in-time node access to record RDP connections."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A ClientToken outside the documented 1-64 char bound is rejected with ValidationException.
    A ClientToken within bounds instead reaches the account-level just-in-time gate and is denied
    there with AccessDeniedException -- the two boundaries produce different, specific errors."""
    guiconnect = ctx.client("ssm-guiconnect")
    account = _account_id(ctx)
    bucket = _create_recording_bucket(ctx)
    key_arn = _create_kms_key(ctx)

    too_long_token = "x" * 65
    code, message = _error(
        lambda: guiconnect.update_connection_recording_preferences(
            ConnectionRecordingPreferences=_prefs(bucket, account, key_arn),
            ClientToken=too_long_token,
        )
    )
    assert code == "ValidationException", f"expected ValidationException for a 65-char ClientToken, got {code}"
    assert message == _TOKEN_TOO_LONG, f"unexpected ValidationException message: {message!r}"

    valid_token = ctx.unique_name("ctmax-")[:64]
    code2, message2 = _error(
        lambda: guiconnect.update_connection_recording_preferences(
            ConnectionRecordingPreferences=_prefs(bucket, account, key_arn),
            ClientToken=valid_token,
        )
    )
    assert code2 == "AccessDeniedException", f"expected AccessDeniedException for a valid-length token, got {code2}"
    assert message2 == _JIT_DENIED, f"unexpected AccessDeniedException message: {message2!r}"


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
    # S3 CreateBucket rejects an explicit LocationConstraint for us-east-1; this is
    # the API's own region-pinned quirk, not an assumption about deployment region.
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
