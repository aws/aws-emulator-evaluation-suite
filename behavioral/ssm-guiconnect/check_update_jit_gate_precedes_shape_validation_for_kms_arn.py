"""update-jit-gate-precedes-shape-validation-for-kms-arn."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-jit-gate-precedes-shape-validation-for-kms-arn"
GROUP = "error-semantics"
SERVICES = ["ssm-guiconnect"]

_JIT_DENIED = "Just-in-time node access is not enabled. You must set up just-in-time node access to record RDP connections."
_NOT_FOUND = "The following  resource cannot be found: 'ConnectionRecordingPreferences'"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A KMSKeyArn that is not ARN-shaped passes the lenient 1-2048-char constraint and Update is
    denied by the just-in-time gate with AccessDeniedException, not a ValidationException; Get
    returns ResourceNotFoundException before and after."""
    guiconnect = ctx.client("ssm-guiconnect")
    _force_unset(guiconnect)
    before_code, before_message = _error(lambda: guiconnect.get_connection_recording_preferences())
    assert before_code == "ResourceNotFoundException", (
        f"expected no prior configuration before this check's own update attempt, got {before_code}"
    )
    assert before_message == _NOT_FOUND, f"unexpected ResourceNotFoundException message: {before_message!r}"

    account = _account_id(ctx)
    bucket = _create_recording_bucket(ctx)

    code, message = _error(
        lambda: guiconnect.update_connection_recording_preferences(
            ConnectionRecordingPreferences=_prefs(bucket, account, "not-a-valid-kms-arn"),
            ClientToken=ctx.unique_name("bad-")[:64],
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    assert message == _JIT_DENIED, f"unexpected AccessDeniedException message: {message!r}"

    after_code, after_message = _error(lambda: guiconnect.get_connection_recording_preferences())
    assert after_code == "ResourceNotFoundException", (
        f"a malformed KMSKeyArn that slipped past shape validation must not leave partial state, "
        f"but an independent Get returned {after_code}"
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


def _force_unset(guiconnect) -> None:
    from botocore.exceptions import ClientError

    try:
        guiconnect.delete_connection_recording_preferences()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


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
