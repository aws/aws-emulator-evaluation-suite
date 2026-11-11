"""denied-update-leaves-no-partial-state."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "denied-update-leaves-no-partial-state"
GROUP = "e2e"
SERVICES = ["ssm-guiconnect"]

_JIT_DENIED = "Just-in-time node access is not enabled. You must set up just-in-time node access to record RDP connections."
_NOT_FOUND = "The following  resource cannot be found: 'ConnectionRecordingPreferences'"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An Update denied by the account-level just-in-time gate must not mutate any state: Get still
    reports unset before and after the attempt, and a subsequent Delete is still a safe no-op."""
    guiconnect = ctx.client("ssm-guiconnect")
    _force_unset(guiconnect)
    baseline_code, baseline_message = _error(lambda: guiconnect.get_connection_recording_preferences())
    assert baseline_code == "ResourceNotFoundException", (
        f"expected an unset baseline before the denied update, got {baseline_code}"
    )
    assert baseline_message == _NOT_FOUND, f"unexpected ResourceNotFoundException message: {baseline_message!r}"

    account = _account_id(ctx)
    bucket = _create_recording_bucket(ctx)
    key_arn = _create_kms_key(ctx)

    update_code, update_message = _error(
        lambda: guiconnect.update_connection_recording_preferences(
            ConnectionRecordingPreferences=_prefs(bucket, account, key_arn),
            ClientToken=ctx.unique_name("ct-")[:64],
        )
    )
    assert update_code == "AccessDeniedException", f"expected the update to be denied, got {update_code}"
    assert update_message == _JIT_DENIED, f"unexpected AccessDeniedException message: {update_message!r}"

    after_code, after_message = _error(lambda: guiconnect.get_connection_recording_preferences())
    assert after_code == "ResourceNotFoundException", (
        f"a denied update must not have created state, but Get returned {after_code}"
    )
    assert after_message == _NOT_FOUND, f"unexpected ResourceNotFoundException message: {after_message!r}"

    # Delete on an unconfigured account succeeds; any ClientError here fails the check.
    guiconnect.delete_connection_recording_preferences()


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
    s3.put_bucket_tagging(
        Bucket=name,
        Tagging={"TagSet": [{"Key": "SystemsManagerJustInTimeNodeAccessManaged", "Value": "true"}]},
    )

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


def _force_unset(guiconnect) -> None:
    from botocore.exceptions import ClientError

    try:
        guiconnect.delete_connection_recording_preferences()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
