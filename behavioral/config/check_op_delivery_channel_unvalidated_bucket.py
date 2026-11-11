"""op-delivery-channel-unvalidated-bucket."""

from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

# ===== helpers =====
# _ensure_recorder_exists never starts, stops, deletes or reconfigures a recorder or channel it
# did not create.

_CONFIG_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
)
_CONFIG_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"


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


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message", "")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _outcome(fn):
    """Poll probe for a call expected to succeed: "accepted" once it succeeds, else its
    ClientError code. The poll that uses it raises on timeout."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return "accepted"


def _poll_until(probe, predicate, *, timeout_s=120, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _trusts_config_service(doc):
    """True only if the trust policy names the EXACT config.amazonaws.com principal
    (a substring test would also match the third-party service-linked role which
    Config cannot assume for standard recording/delivery)."""
    import urllib.parse as _up

    if isinstance(doc, str):
        try:
            doc = json.loads(_up.unquote(doc))
        except Exception:
            return False
    if not isinstance(doc, dict):
        return False
    for stmt in doc.get("Statement", []):
        principal = stmt.get("Principal", {})
        svc = principal.get("Service") if isinstance(principal, dict) else None
        svcs = svc if isinstance(svc, list) else [svc]
        if "config.amazonaws.com" in svcs:
            return True
    return False


def _ensure_recorder_exists(ctx):
    """Guarantee a configuration recorder EXISTS without ever touching one we did
    not create. A recorder is ACCOUNT-WIDE and billed per configuration item, so
    it is never started here; PutDeliveryChannel only needs one to exist."""
    cfg = ctx.client("config")
    existing = _retry_throttled(cfg.describe_configuration_recorders).get(
        "ConfigurationRecorders", []
    )
    if existing:
        return existing[0]["name"], False

    iam = ctx.client("iam")
    role_arn = None
    for name in ("config-role", "AWSConfigRole", "AWSServiceRoleForConfig"):
        try:
            role = iam.get_role(RoleName=name)["Role"]
        except ClientError:
            continue
        if _trusts_config_service(role.get("AssumeRolePolicyDocument")):
            role_arn = role["Arn"]
            break
    if role_arn is None:
        created_role = ctx.unique_name("sim2real-behav-cfg-role-")
        try:
            role_arn = iam.create_role(
                RoleName=created_role,
                AssumeRolePolicyDocument=_CONFIG_TRUST_POLICY,
                Description="sim2real behavioral fidelity probe role for AWS Config",
                Tags=[{"Key": "sim2real:behavioral-check", "Value": CHECK}],
            )["Role"]["Arn"]
        except ClientError as exc:
            raise AssertionError(
                "no AWS Config service role exists in this account and the caller "
                "lacks iam:CreateRole, so no configuration recorder can be created: "
                f"{exc.response.get('Error', {}).get('Code')}"
            ) from exc
        ctx.on_cleanup(lambda r=created_role: iam.delete_role(RoleName=r))
        try:
            iam.attach_role_policy(RoleName=created_role, PolicyArn=_CONFIG_MANAGED_POLICY_ARN)
            ctx.on_cleanup(
                lambda r=created_role: iam.detach_role_policy(
                    RoleName=r, PolicyArn=_CONFIG_MANAGED_POLICY_ARN
                )
            )
        except ClientError:
            pass

    recorder = ctx.unique_name("sim2real-behav-cfg-recorder-")
    # IAM role creation is eventually consistent and Config validates the pass-role
    # at Put time; retry the FIRST use of a brand-new role to a bounded deadline
    # instead of sleeping blind.
    deadline = time.monotonic() + 120
    last = None
    while time.monotonic() < deadline:
        try:
            _retry_throttled(
                lambda: cfg.put_configuration_recorder(
                    ConfigurationRecorder={
                        "name": recorder,
                        "roleARN": role_arn,
                        # An INCLUSION recording group must name at least one type:
                        # allSupported=False with an EMPTY resourceTypes list is refused
                        # with InvalidRecordingGroupException (measured on real AWS), as is
                        # allSupported=True alongside resourceTypes. One narrow type keeps
                        # the prerequisite recorder cheap.
                        "recordingGroup": {
                            "allSupported": False,
                            "resourceTypes": ["AWS::S3::Bucket"],
                        },
                    }
                )
            )
            break
        except ClientError as exc:
            last = exc
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("InsufficientPermissionsException", "ValidationException"):
                raise
            time.sleep(5)
    else:
        raise AssertionError(f"could not create a configuration recorder within 120s: {last!r}")
    ctx.on_cleanup(
        lambda r=recorder: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=r)
        )
    )
    return recorder, True


def _delivery_policy(bucket, account):
    """The exact bucket policy AWS Config requires on a delivery bucket."""
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AWSConfigBucketPermissionsCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "config.amazonaws.com"},
                    "Action": "s3:GetBucketAcl",
                    "Resource": f"arn:aws:s3:::{bucket}",
                    "Condition": {"StringEquals": {"AWS:SourceAccount": account}},
                },
                {
                    "Sid": "AWSConfigBucketExistenceCheck",
                    "Effect": "Allow",
                    "Principal": {"Service": "config.amazonaws.com"},
                    "Action": "s3:ListBucket",
                    "Resource": f"arn:aws:s3:::{bucket}",
                    "Condition": {"StringEquals": {"AWS:SourceAccount": account}},
                },
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
                },
            ],
        }
    )


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


CHECK = "op-delivery-channel-unvalidated-bucket"
GROUP = "overly-permissive"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutDeliveryChannel succeeds against a real, policied bucket but refuses a never-existing bucket
    with NoSuchBucketException, and the refused update leaves the valid channel target in place."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]

    if _retry_throttled(cfg.describe_delivery_channels).get("DeliveryChannels", []):
        raise AssertionError(
            "account already holds the single permitted delivery channel; "
            "reconfiguring or deleting it would be destructive to another tenant"
        )

    _ensure_recorder_exists(ctx)

    bucket = ctx.unique_name("sim2real-behav-cfg-delivery-").replace("_", "-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda b=bucket: _drop_bucket(s3, b))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real:behavioral-check", "Value": CHECK}]},
    )
    s3.put_bucket_policy(Bucket=bucket, Policy=_delivery_policy(bucket, account))

    channel_name = ctx.unique_name("sim2real-behav-cfg-channel-")

    # 1. Positive control: PutDeliveryChannel against a real, correctly-policied
    #    bucket must succeed -- without this, a target that rejects every call
    #    would score identically to a correct one on the negative below.
    _poll_until(
        lambda: _outcome(
            lambda: _retry_throttled(
                lambda: cfg.put_delivery_channel(
                    DeliveryChannel={"name": channel_name, "s3BucketName": bucket}
                )
            )
        ),
        lambda outcome: outcome == "accepted",
        timeout_s=180,
        interval_s=5.0,
        description="PutDeliveryChannel accepted against a valid, correctly-policied bucket",
    )
    ctx.on_cleanup(
        lambda c=channel_name: _retry_throttled(
            lambda: cfg.delete_delivery_channel(DeliveryChannelName=c)
        )
    )
    described = _retry_throttled(cfg.describe_delivery_channels)["DeliveryChannels"]
    assert [c["name"] for c in described] == [channel_name], described
    assert described[0]["s3BucketName"] == bucket, described[0]

    # 2. Break exactly one thing: point the SAME channel at a bucket that has
    #    never existed. Everything else -- name, recorder, account -- is
    #    identical to the accepted call above.
    bogus_bucket = ctx.unique_name("sim2real-behav-cfg-absent-bucket-").replace("_", "-").lower()
    code, message = _error(
        lambda: _retry_throttled(
            lambda: cfg.put_delivery_channel(
                DeliveryChannel={"name": channel_name, "s3BucketName": bogus_bucket}
            )
        )
    )
    assert code == "NoSuchBucketException", (
        f"PutDeliveryChannel onto a bucket that does not exist must be refused "
        f"with NoSuchBucketException; got {code!r}"
    )
    assert message == f"No such s3 bucket with name '{bogus_bucket}'.", message

    # 3. Effect absent: the refused update must not have touched the channel --
    #    it still points at the valid bucket, not the bogus one and not neither.
    described = _retry_throttled(cfg.describe_delivery_channels)["DeliveryChannels"]
    assert [c["name"] for c in described] == [channel_name], described
    assert described[0]["s3BucketName"] == bucket, (
        f"a refused PutDeliveryChannel must leave the existing valid target in "
        f"place; got {described[0]!r}"
    )

    # 4. Control still works: the identical valid call succeeds again, so the
    #    refusal above is attributable to the bogus bucket alone.
    _retry_throttled(
        lambda: cfg.put_delivery_channel(
            DeliveryChannel={"name": channel_name, "s3BucketName": bucket}
        )
    )
    final = _retry_throttled(cfg.describe_delivery_channels)["DeliveryChannels"]
    assert [c["name"] for c in final] == [channel_name], final
    assert final[0]["s3BucketName"] == bucket, final[0]


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
