"""update-denial-is-stable-across-retries-with-same-client-token."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-denial-is-stable-across-retries-with-same-client-token"
GROUP = "state"
SERVICES = ["ssm-guiconnect"]

_JIT_DENIED = "Just-in-time node access is not enabled. You must set up just-in-time node access to record RDP connections."
_NOT_FOUND = "The following  resource cannot be found: 'ConnectionRecordingPreferences'"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Retrying a denied Update with the identical ClientToken and payload is denied the same way
    both times -- the just-in-time gate is deterministic and a retried request never surfaces
    ConflictException."""
    guiconnect = ctx.client("ssm-guiconnect")
    account = _account_id(ctx)
    bucket = _create_recording_bucket(ctx)
    key_arn = _create_kms_key(ctx)
    prefs = _prefs(bucket, account, key_arn)
    token = ctx.unique_name("idem-")[:64]

    code1, message1 = _error(
        lambda: guiconnect.update_connection_recording_preferences(
            ConnectionRecordingPreferences=prefs, ClientToken=token
        )
    )
    code2, message2 = _error(
        lambda: guiconnect.update_connection_recording_preferences(
            ConnectionRecordingPreferences=prefs, ClientToken=token
        )
    )
    assert code1 == "AccessDeniedException", f"expected denial, got {code1}"
    assert message1 == _JIT_DENIED, f"unexpected AccessDeniedException message: {message1!r}"
    assert code2 == code1, f"retry with the same ClientToken gave a different error: {code1} vs {code2}"
    assert message2 == message1, f"retry with the same ClientToken gave a different message: {message2!r}"

    # Independent read at a different operation: proves the credential is otherwise healthy for
    # this service (Get is not itself AccessDenied) and that neither denied Update left partial state.
    get_code, get_message = _error(lambda: guiconnect.get_connection_recording_preferences())
    assert get_code == "ResourceNotFoundException", (
        f"two denied Updates must leave no partial state, but Get returned {get_code}"
    )
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
