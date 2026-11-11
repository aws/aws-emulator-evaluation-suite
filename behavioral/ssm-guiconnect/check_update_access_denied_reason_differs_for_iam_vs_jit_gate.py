"""update-access-denied-reason-differs-for-iam-vs-jit-gate."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-access-denied-reason-differs-for-iam-vs-jit-gate"
GROUP = "overly-permissive"
SERVICES = ["ssm-guiconnect"]

_NOT_FOUND = "The following  resource cannot be found: 'ConnectionRecordingPreferences'"
_JIT_DENIED = "Just-in-time node access is not enabled. You must set up just-in-time node access to record RDP connections."
_IAM_DENIED_UPDATE = (
    "User: {user_arn} is not authorized to perform: ssm-guiconnect:UpdateConnectionRecordingPreferences on resource: "
    "arn:{partition}:ec2:{region}:{account}:instance/* because no identity-based policy allows the "
    "ssm-guiconnect:UpdateConnectionRecordingPreferences action"
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Update denied by the account-level just-in-time node access gate for a permissioned principal and
    Update by a principal with no ssm-guiconnect permissions both fail with AccessDeniedException but
    with different exact messages, and Get afterwards reports the state unchanged."""
    guiconnect = ctx.client("ssm-guiconnect")
    iam = ctx.client("iam")

    account = _account_id(ctx)
    bucket = _create_recording_bucket(ctx)
    key_arn = _create_kms_key(ctx)

    # positive control: this permissioned principal is not denied ssm-guiconnect wholesale --
    # only Update is blocked by the account-level JIT gate, so Get must still be reachable.
    baseline_code, baseline_message = _error(lambda: guiconnect.get_connection_recording_preferences())
    assert baseline_code == "ResourceNotFoundException", (
        f"expected the permissioned principal's Get to report unset, got {baseline_code}"
    )
    assert baseline_message == _NOT_FOUND, f"unexpected ResourceNotFoundException message: {baseline_message!r}"

    # (a) permissioned principal, denied by the JIT gate
    jit_code, jit_message = _error(
        lambda: guiconnect.update_connection_recording_preferences(
            ConnectionRecordingPreferences=_prefs(bucket, account, key_arn),
            ClientToken=ctx.unique_name("jit-")[:64],
        )
    )
    assert jit_code == "AccessDeniedException", (
        f"expected the permissioned call to be denied with AccessDeniedException, got {jit_code}"
    )
    assert jit_message == _JIT_DENIED, f"expected the just-in-time-node-access message, got: {jit_message!r}"

    # (b) no ssm-guiconnect IAM permissions at all
    user_name = ctx.unique_name("sim2real-guic-nodeny-")
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    restricted = ctx.client(
        "ssm-guiconnect",
        creds={"aws_access_key_id": key["AccessKeyId"], "aws_secret_access_key": key["SecretAccessKey"]},
    )

    code, message = _poll_for_stable_error(
        lambda: restricted.update_connection_recording_preferences(
            ConnectionRecordingPreferences=_prefs(bucket, account, key_arn),
            ClientToken=ctx.unique_name("iam-")[:64],
        ),
        timeout_s=30.0,
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    partition, user_account = user_arn.split(":")[1], user_arn.split(":")[4]
    expected = _IAM_DENIED_UPDATE.format(user_arn=user_arn, partition=partition, region=ctx.region, account=user_account)
    assert message == expected, f"expected the IAM-permission denial {expected!r}, got: {message!r}"
    assert message != jit_message, (
        "IAM-permission denial and JIT-gate denial must not share the exact same message"
    )

    # terminal: an independent read at the destination proves neither denied Update mutated
    # state -- Get still reports exactly what it did before either attempt.
    after = _error(lambda: guiconnect.get_connection_recording_preferences())
    assert after == (baseline_code, baseline_message), (
        f"a denied Update must not change state visible to Get: "
        f"before={(baseline_code, baseline_message)!r} after={after!r}"
    )


def _error(fn) -> tuple[str, str]:
    """The (code, message) of the ClientError ``fn`` raises; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _poll_for_stable_error(fn, timeout_s: float):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last = (None, None)
    while time.monotonic() < deadline:
        try:
            fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            last = (code, message)
            if code not in ("InvalidClientTokenId", "UnrecognizedClientException"):
                return last
        else:
            raise AssertionError("expected the call to be refused, but it succeeded")
        time.sleep(2.0)
    raise AssertionError(f"the new access key never finished propagating within {timeout_s}s; last {last!r}")


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
