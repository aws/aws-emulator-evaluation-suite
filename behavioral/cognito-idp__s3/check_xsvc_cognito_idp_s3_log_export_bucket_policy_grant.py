"""xsvc-cognito-idp-s3-log-export-bucket-policy-grant."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "xsvc-cognito-idp-s3-log-export-bucket-policy-grant"
GROUP = "log-delivery"
SERVICES = ["cognito-idp", "s3"]

_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-xsvc"}
_INVALID_DESTINATION = "Invalid destination in the input."


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _retry_throttled(fn, *, attempts: int = 8):
    delay = 1.0
    for i in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "TooManyRequestsException" and i < attempts - 1:
                time.sleep(delay)
                delay = min(delay * 1.7, 15.0)
                continue
            raise


def _create_bucket(ctx, s3, bucket: str) -> None:
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})


def _new_bucket(ctx, s3, prefix: str) -> str:
    bucket = ctx.unique_name(prefix)[:63].lower()
    _create_bucket(ctx, s3, bucket)
    return bucket


def _empty_and_delete_bucket(s3, bucket: str) -> None:
    """Teardown: remove anything Cognito's log delivery wrote, then the bucket itself."""
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]}
                for v in page.get("Versions", []) + page.get("DeleteMarkers", [])]
        if objs:
            s3.delete_objects(Bucket=bucket, Delete={"Objects": objs, "Quiet": True})
    s3.delete_bucket(Bucket=bucket)


def _s3_configs(idp, pool_id: str) -> list:
    return idp.get_log_delivery_configuration(UserPoolId=pool_id)[
        "LogDeliveryConfiguration"].get("LogConfigurations", [])


def _s3_log_config(bucket_arn: str) -> dict:
    return {"EventSource": "userAuthEvents", "LogLevel": "INFO",
            "S3Configuration": {"BucketArn": bucket_arn}}


def _set_destination(idp, pool_id: str, bucket_arn: str, *, budget_s: float = 30.0) -> None:
    """SetLogDeliveryConfiguration for a bucket that exists; bounded-retries both throttling and
    Cognito's own propagation delay in recognizing a bucket this check just created."""
    deadline = time.monotonic() + budget_s
    delay = 1.0
    while True:
        try:
            idp.set_log_delivery_configuration(
                UserPoolId=pool_id, LogConfigurations=[_s3_log_config(bucket_arn)])
            return
        except ClientError as exc:
            err = exc.response.get("Error", {})
            retryable = (err.get("Code") == "TooManyRequestsException"
                         or (err.get("Code"), err.get("Message"))
                         == ("InvalidParameterException", _INVALID_DESTINATION))
            if not retryable or time.monotonic() >= deadline:
                raise
            time.sleep(delay)
            delay = min(delay * 1.5, 5.0)


def _delivery_grants(s3, bucket: str) -> list:
    """The delivery.logs.amazonaws.com statements Cognito wrote onto the bucket's own policy."""
    policy = json.loads(s3.get_bucket_policy(Bucket=bucket)["Policy"])
    stmts = [s for s in policy.get("Statement", [])
             if (s.get("Principal") or {}).get("Service") == "delivery.logs.amazonaws.com"]
    assert len(stmts) == 2, (
        f"expected exactly two delivery.logs.amazonaws.com statements on {bucket!r}'s policy "
        f"(write + ACL check), got {policy.get('Statement')!r}")
    return stmts


def _assert_delivery_grants(ctx, s3, bucket: str, bucket_arn: str) -> None:
    """The write grant lets the log-delivery service PutObject under this bucket's AWSLogs
    prefix for this account; the ACL-check grant lets it read the bucket's own ACL first."""
    by_action = {g["Action"]: g for g in _delivery_grants(s3, bucket)}
    assert set(by_action) == {"s3:PutObject", "s3:GetBucketAcl"}, (
        f"grant actions {sorted(by_action)}, expected s3:PutObject and s3:GetBucketAcl")

    write = by_action["s3:PutObject"]
    assert write.get("Effect") == "Allow", f"write grant is not Allow: {write!r}"
    assert write.get("Resource") == f"{bucket_arn}/AWSLogs/{ctx.account}/*", (
        f"write grant resource {write.get('Resource')!r}, expected {bucket_arn}/AWSLogs/{ctx.account}/*")
    write_cond = write.get("Condition") or {}
    assert write_cond.get("StringEquals", {}).get("aws:SourceAccount") == ctx.account, (
        f"write grant's aws:SourceAccount {write_cond.get('StringEquals')!r}, expected {ctx.account!r}")
    assert write_cond.get("StringEquals", {}).get("s3:x-amz-acl") == "bucket-owner-full-control", (
        f"write grant's s3:x-amz-acl condition {write_cond.get('StringEquals')!r}")
    assert write_cond.get("ArnLike", {}).get("aws:SourceArn") == f"arn:aws:logs:{ctx.region}:{ctx.account}:*", (
        f"write grant's aws:SourceArn {write_cond.get('ArnLike')!r}")

    acl_check = by_action["s3:GetBucketAcl"]
    assert acl_check.get("Effect") == "Allow", f"ACL-check grant is not Allow: {acl_check!r}"
    assert acl_check.get("Resource") == bucket_arn, (
        f"ACL-check grant resource {acl_check.get('Resource')!r}, expected {bucket_arn!r}")
    acl_cond = acl_check.get("Condition") or {}
    assert acl_cond.get("StringEquals", {}).get("aws:SourceAccount") == ctx.account, (
        f"ACL-check grant's aws:SourceAccount {acl_cond.get('StringEquals')!r}, expected {ctx.account!r}")
    assert acl_cond.get("ArnLike", {}).get("aws:SourceArn") == f"arn:aws:logs:{ctx.region}:{ctx.account}:*", (
        f"ACL-check grant's aws:SourceArn {acl_cond.get('ArnLike')!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Cognito accepts a userAuthEvents S3 log destination only while the bucket exists, and on
    acceptance grants delivery.logs.amazonaws.com write access on the bucket's own policy, a
    grant that clearing the destination later leaves in place rather than revoking.

    Reference: https://docs.aws.amazon.com/cognito/latest/developerguide/exporting-quotas-and-usage.html
    """
    idp = ctx.client("cognito-idp")
    s3 = ctx.client("s3")

    bucket_a = _new_bucket(ctx, s3, "sim2real-xsvc-cip-s3-a-")
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_a))
    s3.put_bucket_tagging(Bucket=bucket_a, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "xsvc-cognito-idp-s3-log-export"}]})
    arn_a = f"arn:aws:s3:::{bucket_a}"

    pool_id = _retry_throttled(lambda: idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-xsvc-cip-s3-pool-"),
        UserPoolTier="PLUS",
        UserPoolTags=_TAGS,
    ))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    tier = idp.describe_user_pool(UserPoolId=pool_id)["UserPool"].get("UserPoolTier")
    assert tier == "PLUS", f"pool was created with UserPoolTier={tier!r}, expected 'PLUS'"

    # Positive control: a real bucket is accepted, and Cognito grants itself write access on it.
    _set_destination(idp, pool_id, arn_a)
    configured = _s3_configs(idp, pool_id)
    assert len(configured) == 1, f"expected exactly one log configuration, got {configured!r}"
    dest_a = (configured[0].get("S3Configuration") or {}).get("BucketArn")
    assert dest_a == arn_a, f"destination read back {dest_a!r}, expected {arn_a!r}"

    _assert_delivery_grants(ctx, s3, bucket_a, arn_a)

    # Break exactly one thing: a bucket name that was never created.
    ghost_bucket = ctx.unique_name("sim2real-xsvc-cip-s3-ghost-")[:63].lower()
    ghost_arn = f"arn:aws:s3:::{ghost_bucket}"
    code, msg = _error(lambda: idp.set_log_delivery_configuration(
        UserPoolId=pool_id, LogConfigurations=[_s3_log_config(ghost_arn)]))
    assert code == "InvalidParameterException", (
        f"a never-created bucket as destination: expected InvalidParameterException, "
        f"got {code!r} ({msg!r})")
    assert msg == _INVALID_DESTINATION, (
        f"a never-created bucket as destination: expected message {_INVALID_DESTINATION!r}, "
        f"got {msg!r}")

    # The refused destination must not have replaced the configured one, and grants nothing.
    after_ghost = _s3_configs(idp, pool_id)
    assert after_ghost == configured, (
        f"a refused destination changed the stored configuration: {after_ghost!r}")
    code, msg = _error(lambda: s3.get_bucket_policy(Bucket=ghost_bucket))
    assert code == "NoSuchBucket", (
        f"the never-created bucket unexpectedly resolves: {code!r} ({msg!r})")

    # Restore: the identical call succeeds once the destination exists for real.
    _create_bucket(ctx, s3, ghost_bucket)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, ghost_bucket))
    s3.put_bucket_tagging(Bucket=ghost_bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "xsvc-cognito-idp-s3-log-export"}]})
    _set_destination(idp, pool_id, ghost_arn)
    repointed = _s3_configs(idp, pool_id)
    assert len(repointed) == 1, f"expected exactly one log configuration, got {repointed!r}"
    dest_ghost = (repointed[0].get("S3Configuration") or {}).get("BucketArn")
    assert dest_ghost == ghost_arn, f"destination read back {dest_ghost!r}, expected {ghost_arn!r}"

    _assert_delivery_grants(ctx, s3, ghost_bucket, ghost_arn)

    # Clearing the destination removes it from the pool's own configuration, but does not
    # revoke the write access it already granted on the bucket's resource policy.
    _retry_throttled(lambda: idp.set_log_delivery_configuration(UserPoolId=pool_id, LogConfigurations=[]))
    cleared = _s3_configs(idp, pool_id)
    assert cleared == [], f"delivery not cleared: {cleared!r}"
    _assert_delivery_grants(ctx, s3, ghost_bucket, ghost_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
