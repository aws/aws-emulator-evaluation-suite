"""delivery-channel-bucket-policy-statement-required."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

# _ensure_recorder_exists never starts, stops, deletes or reconfigures a recorder or channel it
# did not create.


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    # Config's control plane has a very low burst limit; churning recorders/rules/
    # delivery-channels across checks reliably trips ThrottlingException. Retry those
    # transparently while re-raising any domain error a check asserts on.
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("ThrottlingException", "TooManyRequestsException"):
                raise
            last = exc
            time.sleep(base_delay * (2 ** min(attempt, 4)))
    raise last


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _error(fn):
    """Return (code, message) of the rejection; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _accepted(fn, retry_codes=("InsufficientDeliveryPolicyException",)):
    """True once fn() succeeds; False on a retryable propagation refusal; any other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") in retry_codes:
            return False
        raise
    return True


def _config_slr_arn(ctx):
    """The AWS Config service-linked role's ARN; the check creates it when the account lacks it."""
    iam = ctx.client("iam")
    try:
        return iam.create_service_linked_role(AWSServiceName="config.amazonaws.com")["Role"]["Arn"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") != "InvalidInput" or "has been taken" not in err.get("Message", ""):
            raise
    return iam.get_role(RoleName="AWSServiceRoleForConfig")["Role"]["Arn"]


def _ensure_recorder_exists(ctx):
    """Ensure a configuration recorder exists, never touching one we did not create.

    PutDeliveryChannel needs a recorder to exist, not to run; an unstarted recorder is not billed.
    """
    cfg = ctx.client("config")
    existing = _retry_throttled(cfg.describe_configuration_recorders).get(
        "ConfigurationRecorders", []
    )
    if existing:
        return existing[0]["name"], False

    role_arn = _config_slr_arn(ctx)

    recorder = ctx.unique_name("sim2real-behav-cfg-recorder-")
    # IAM role creation is eventually consistent and Config validates the pass-role
    # at Put time, so the first use of a new role is retried to a bounded deadline.
    deadline = time.monotonic() + 120
    last = None
    while time.monotonic() < deadline:
        try:
            _retry_throttled(
                lambda: cfg.put_configuration_recorder(
                    ConfigurationRecorder={
                        "name": recorder,
                        "roleARN": role_arn,
                        # allSupported=False with an empty resourceTypes list is refused with
                        # InvalidRecordingGroupException; one narrow type keeps the recorder cheap.
                        "recordingGroup": {
                            "allSupported": False,
                            "resourceTypes": ["AWS::S3::Bucket"],
                        },
                    },
                    Tags=[{"Key": "sim2real", "Value": CHECK}],
                )
            )
            break
        except ClientError as exc:
            last = exc
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in (
                "InsufficientPermissionsException",
                "InvalidRoleException",
                "ValidationException",
            ):
                raise
            time.sleep(5)
    else:
        raise AssertionError(
            f"could not create a configuration recorder within 120s: {last!r}"
        )
    ctx.on_cleanup(
        lambda r=recorder: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=r)
        )
    )
    return recorder, True


def _delivery_policy(bucket, account, include_get_bucket_acl=True):
    """The exact bucket policy AWS Config requires on a delivery bucket."""
    statements = []
    if include_get_bucket_acl:
        statements.append(
            {
                "Sid": "AWSConfigBucketPermissionsCheck",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket}",
                "Condition": {"StringEquals": {"AWS:SourceAccount": account}},
            }
        )
    statements.append(
        {
            "Sid": "AWSConfigBucketExistenceCheck",
            "Effect": "Allow",
            "Principal": {"Service": "config.amazonaws.com"},
            "Action": "s3:ListBucket",
            "Resource": f"arn:aws:s3:::{bucket}",
            "Condition": {"StringEquals": {"AWS:SourceAccount": account}},
        }
    )
    statements.append(
        {
            "Sid": "AWSConfigBucketDelivery",
            "Effect": "Allow",
            "Principal": {"Service": "config.amazonaws.com"},
            "Action": "s3:PutObject",
            "Resource": f"arn:aws:s3:::{bucket}/AWSLogs/{account}/Config/*",
            "Condition": {
                "StringEquals": {
                    "s3:x-amz-acl": "bucket-owner-full-control",
                    "AWS:SourceAccount": account,
                }
            },
        }
    )
    return json.dumps({"Version": "2012-10-17", "Statement": statements})


CHECK = "delivery-channel-bucket-policy-statement-required"
GROUP = 'delivery-channel'
SERVICES = ['config']
# S3 is setup only: a delivery channel needs a bucket whose policy trusts config.amazonaws.com.


@tags("axis:rejection", "cap:c7", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutDeliveryChannel refuses a bucket policy lacking s3:GetBucketAcl for config.amazonaws.com
    with InsufficientDeliveryPolicyException, creates no channel, and accepts the identical
    request once that statement is restored: Config reads the bucket policy before accepting.
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    existing_channels = _retry_throttled(cfg.describe_delivery_channels).get(
        "DeliveryChannels", []
    )
    if existing_channels:
        # AWS Config permits exactly ONE delivery channel per account per region.
        # Putting over the incumbent would repoint another tenant's snapshot and
        # history delivery at our bucket; deleting it would break their recorder.
        raise AssertionError(
            "account already holds the single permitted delivery channel "
            f"({existing_channels[0].get('name')!r}); reconfiguring or deleting it "
            "would be destructive to another tenant"
        )

    _ensure_recorder_exists(ctx)

    bucket = ctx.unique_name("sim2real-behav-cfg-delivery-")
    kwargs = {"Bucket": bucket}
    # us-east-1 is CreateBucket's own no-LocationConstraint default; this is S3's
    # API quirk, not a pinned resource region -- ctx.region drives every other call.
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})
    # The recorder is never started, so the bucket stays empty; a bulk delete is the fallback.
    ctx.on_cleanup(lambda b=bucket: _drop_bucket(s3, b))

    channel = ctx.unique_name("sim2real-behav-cfg-channel-")

    # 1. Valid setup: the complete policy Config documents as required.
    s3.put_bucket_policy(
        Bucket=bucket, Policy=_delivery_policy(bucket, account, include_get_bucket_acl=True)
    )
    _poll_until(
        lambda: _accepted(
            lambda: _retry_throttled(
                lambda: cfg.put_delivery_channel(
                    DeliveryChannel={"name": channel, "s3BucketName": bucket}
                )
            )
        ),
        lambda ok: ok is True,
        timeout_s=120,
        interval_s=5.0,
        description="PutDeliveryChannel accepted with the complete Config bucket policy",
    )
    ctx.on_cleanup(
        lambda c=channel: _retry_throttled(
            lambda: cfg.delete_delivery_channel(DeliveryChannelName=c)
        )
    )
    described = _retry_throttled(cfg.describe_delivery_channels)["DeliveryChannels"]
    assert [c["name"] for c in described] == [channel], (
        f"the control channel must be the only channel present, got {described!r}"
    )
    assert described[0]["s3BucketName"] == bucket, described[0]

    # Take the channel back down so the negative below is testing the policy
    # check and not MaxNumberOfDeliveryChannelsExceededException.
    _retry_throttled(lambda: cfg.delete_delivery_channel(DeliveryChannelName=channel))
    assert _retry_throttled(cfg.describe_delivery_channels)["DeliveryChannels"] == [], (
        "the channel must be gone before the negative leg begins"
    )

    # 2. Break exactly one thing: drop the s3:GetBucketAcl statement. Everything
    #    else -- the bucket, the PutObject grant, the recorder, the request --
    #    is byte-identical to the accepted call above.
    s3.put_bucket_policy(
        Bucket=bucket,
        Policy=_delivery_policy(bucket, account, include_get_bucket_acl=False),
    )
    # The policy change reaches Config's pre-check after a propagation delay, so the put is
    # retried (bounded) until it is refused; a put accepted on the old policy is removed again.
    def _put_once():
        try:
            _retry_throttled(
                lambda: cfg.put_delivery_channel(
                    DeliveryChannel={"name": channel, "s3BucketName": bucket}
                )
            )
        except ClientError as exc:
            err = exc.response.get("Error", {})
            return err.get("Code"), err.get("Message")
        _retry_throttled(lambda: cfg.delete_delivery_channel(DeliveryChannelName=channel))
        return None

    code, message = _poll_until(
        _put_once,
        lambda r: r is not None,
        timeout_s=120,
        interval_s=5.0,
        description="PutDeliveryChannel refused once s3:GetBucketAcl is gone from the policy",
    )
    assert code == "InsufficientDeliveryPolicyException", (
        f"removing only the s3:GetBucketAcl grant for config.amazonaws.com must be "
        f"refused with InsufficientDeliveryPolicyException; got {code!r}"
    )
    assert message == (
        f"Insufficient delivery policy to s3 bucket: {bucket}, unable to get s3 bucket acl."
    ), message

    # 3. Effect absent: the refusal must not have created a channel.
    assert _retry_throttled(cfg.describe_delivery_channels)["DeliveryChannels"] == [], (
        "a refused PutDeliveryChannel must create no delivery channel"
    )
    missing = _error(lambda: cfg.describe_delivery_channels(DeliveryChannelNames=[channel]))
    assert missing == (
        "NoSuchDeliveryChannelException",
        f"Cannot find delivery channel with specified name '{channel}'.",
    ), f"the refused channel name must not resolve, got {missing!r}"

    # 4. Control still works: restoring that single statement makes the identical
    #    request succeed again, proving the refusal was attributable to it alone.
    s3.put_bucket_policy(
        Bucket=bucket, Policy=_delivery_policy(bucket, account, include_get_bucket_acl=True)
    )
    _poll_until(
        lambda: _accepted(
            lambda: _retry_throttled(
                lambda: cfg.put_delivery_channel(
                    DeliveryChannel={"name": channel, "s3BucketName": bucket}
                )
            )
        ),
        lambda ok: ok is True,
        timeout_s=120,
        interval_s=5.0,
        description="PutDeliveryChannel accepted again after restoring s3:GetBucketAcl",
    )
    final = _retry_throttled(cfg.describe_delivery_channels)["DeliveryChannels"]
    assert [c["name"] for c in final] == [channel], final


def _drop_bucket(s3, bucket):
    try:
        s3.delete_bucket(Bucket=bucket)
        return
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "BucketNotEmpty":
            raise
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys = [{"Key": o["Key"]} for o in page.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket)


def _restore_config_recorder_on_teardown(ctx) -> None:
    """The Config recorder and delivery channel exist once per account and Region: read them now
    and, in a teardown that runs after the check's own, put back exactly what was there."""
    import time

    from botocore.exceptions import ClientError

    cfg = ctx.client("config")

    def _call(fn):
        deadline = time.monotonic() + 60.0
        while True:
            try:
                return fn()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ThrottlingException" or time.monotonic() > deadline:
                    raise
                time.sleep(2.0)

    def _recorders():
        found = _call(cfg.describe_configuration_recorders)["ConfigurationRecorders"]
        return [r for r in found if not r.get("servicePrincipal")]

    recorders = _recorders()
    statuses = _call(cfg.describe_configuration_recorder_status)["ConfigurationRecordersStatus"]
    recording = {s["name"] for s in statuses if s.get("recording")}
    channels = _call(cfg.describe_delivery_channels)["DeliveryChannels"]
    fields = ("name", "roleARN", "recordingGroup", "recordingMode")

    def _restore() -> None:
        now = _recorders()
        for r in now:
            _call(lambda n=r["name"]: cfg.stop_configuration_recorder(ConfigurationRecorderName=n))
        kept = {c["name"] for c in channels}
        for c in _call(cfg.describe_delivery_channels)["DeliveryChannels"]:
            if c["name"] not in kept:
                _call(lambda n=c["name"]: cfg.delete_delivery_channel(DeliveryChannelName=n))
        kept = {r["name"] for r in recorders}
        for r in now:
            if r["name"] not in kept:
                _call(lambda n=r["name"]: cfg.delete_configuration_recorder(ConfigurationRecorderName=n))
        for r in recorders:
            body = {k: v for k, v in r.items() if k in fields}
            _call(lambda b=body: cfg.put_configuration_recorder(ConfigurationRecorder=b))
        for c in channels:
            _call(lambda c=c: cfg.put_delivery_channel(DeliveryChannel=c))
        for r in recorders:
            if r["name"] in recording:
                _call(lambda n=r["name"]: cfg.start_configuration_recorder(ConfigurationRecorderName=n))

    ctx.on_cleanup(_restore)



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
