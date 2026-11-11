"""update-shape-validation-precedes-jit-gate-for-bucket-owner."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "update-shape-validation-precedes-jit-gate-for-bucket-owner"
GROUP = "overly-permissive"
SERVICES = ["ssm-guiconnect"]

_JIT_DENIED = "Just-in-time node access is not enabled. You must set up just-in-time node access to record RDP connections."
_BAD_BUCKET_OWNER = "The value provided for ConnectionRecordingPreferences.RecordingDestinations.S3Buckets.BucketOwner isn't valid."


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A BucketOwner that is not a 12-digit account id is rejected with ValidationException ahead
    of the account-level just-in-time gate, which denies the same call with a valid BucketOwner
    with AccessDeniedException."""
    guiconnect = ctx.client("ssm-guiconnect")
    account = _account_id(ctx)
    bucket_name = ctx.unique_name("sim2real-guic-")
    kms_arn = f"arn:aws:kms:{ctx.region}:{account}:key/00000000-0000-0000-0000-000000000000"

    control_code, control_message = _error(
        lambda: guiconnect.update_connection_recording_preferences(
            ConnectionRecordingPreferences=_prefs(bucket_name, account, kms_arn),
            ClientToken=ctx.unique_name("good-")[:64],
        )
    )
    assert control_code == "AccessDeniedException", (
        f"positive control: a valid BucketOwner should pass shape validation and reach the JIT "
        f"gate (AccessDeniedException), got {control_code}"
    )
    assert control_message == _JIT_DENIED, f"unexpected AccessDeniedException message: {control_message!r}"

    code, message = _error(
        lambda: guiconnect.update_connection_recording_preferences(
            ConnectionRecordingPreferences=_prefs(bucket_name, "abcdefghijkl", kms_arn),
            ClientToken=ctx.unique_name("bad-")[:64],
        )
    )
    assert code == "ValidationException", f"expected ValidationException for a malformed bucket owner, got {code}"
    assert message == _BAD_BUCKET_OWNER, f"unexpected ValidationException message: {message!r}"


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


def _prefs(bucket_name: str, bucket_owner: str, kms_arn: str) -> dict[str, Any]:
    return {
        "RecordingDestinations": {"S3Buckets": [{"BucketName": bucket_name, "BucketOwner": bucket_owner}]},
        "KMSKeyArn": kms_arn,
    }


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
