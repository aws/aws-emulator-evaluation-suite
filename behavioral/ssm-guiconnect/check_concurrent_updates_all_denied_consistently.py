"""concurrent-updates-all-denied-consistently."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-updates-all-denied-consistently"
GROUP = "concurrency"
SERVICES = ["ssm-guiconnect"]

_JIT_DENIED = "Just-in-time node access is not enabled. You must set up just-in-time node access to record RDP connections."
_NOT_FOUND = "The following  resource cannot be found: 'ConnectionRecordingPreferences'"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing several Update calls against the account-level singleton, while just-in-time node access
    is disabled, must deny every single one with AccessDeniedException -- never a partial success and
    never a different error (e.g. ConflictException) leaking through under concurrency."""
    guiconnect = ctx.client("ssm-guiconnect")
    account = _account_id(ctx)

    configs = []
    for _ in range(3):
        bucket = _create_recording_bucket(ctx)
        key_arn = _create_kms_key(ctx)
        configs.append((bucket, key_arn))

    def _attempt(i: int):
        bucket, key_arn = configs[i]
        try:
            guiconnect.update_connection_recording_preferences(
                ConnectionRecordingPreferences=_prefs(bucket, account, key_arn),
                ClientToken=ctx.unique_name(f"race-{i}-")[:64],
            )
            return ("ok", None)
        except Exception as e:  # noqa: BLE001 - classify below
            from botocore.exceptions import ClientError

            if isinstance(e, ClientError):
                return ("error", (e.response["Error"]["Code"], e.response["Error"].get("Message", "")))
            raise

    from concurrent.futures import ThreadPoolExecutor

    with ThreadPoolExecutor(max_workers=3) as pool:
        results = list(pool.map(_attempt, range(3)))

    successes = [r for kind, r in results if kind == "ok"]
    errors = [r for kind, r in results if kind == "error"]

    assert not successes, "an Update succeeded while just-in-time node access is disabled account-wide"
    assert len(errors) == 3, f"expected 3 denials, got {len(errors)} errors: {errors}"
    for code, message in errors:
        assert code == "AccessDeniedException", f"unexpected error under contention: {code}"
        assert message == _JIT_DENIED, f"unexpected denial message under contention: {message!r}"

    # the singleton must remain untouched by any of the racers
    get_code, get_message = _error(lambda: guiconnect.get_connection_recording_preferences())
    assert get_code == "ResourceNotFoundException", f"racers left residual state: {get_code}"
    assert get_message == _NOT_FOUND, f"unexpected ResourceNotFoundException message: {get_message!r}"


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
