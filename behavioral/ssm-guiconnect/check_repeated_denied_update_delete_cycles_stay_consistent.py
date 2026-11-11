"""repeated-denied-update-delete-cycles-stay-consistent."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "repeated-denied-update-delete-cycles-stay-consistent"
GROUP = "state"
SERVICES = ["ssm-guiconnect"]

_JIT_DENIED = "Just-in-time node access is not enabled. You must set up just-in-time node access to record RDP connections."
_NOT_FOUND = "The following  resource cannot be found: 'ConnectionRecordingPreferences'"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Running several denied-Update / Delete cycles back-to-back never flips the account into a
    different state (e.g. a transient success or ConflictException) -- the gate is stable under
    repetition."""
    guiconnect = ctx.client("ssm-guiconnect")
    account = _account_id(ctx)

    for i in range(3):
        bucket = _create_recording_bucket(ctx)
        key_arn = _create_kms_key(ctx)
        update_code, update_message = _error(
            lambda bucket=bucket, key_arn=key_arn, i=i: guiconnect.update_connection_recording_preferences(
                ConnectionRecordingPreferences=_prefs(bucket, account, key_arn),
                ClientToken=ctx.unique_name(f"cycle-{i}-")[:64],
            )
        )
        assert update_code == "AccessDeniedException", f"cycle {i}: expected denial, got {update_code}"
        assert update_message == _JIT_DENIED, f"cycle {i}: unexpected denial message {update_message!r}"

        # Delete on an unconfigured account succeeds; any ClientError here fails the check.
        guiconnect.delete_connection_recording_preferences()

        get_code, get_message = _error(lambda: guiconnect.get_connection_recording_preferences())
        assert get_code == "ResourceNotFoundException", f"cycle {i}: expected unset, got {get_code}"
        assert get_message == _NOT_FOUND, f"cycle {i}: unexpected not-found message {get_message!r}"


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
