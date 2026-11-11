"""deliver-config-snapshot."""

from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

_CONFIG_ROLE_NAME = "sim2real-behav-config-role"
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
_ROLE_ARN_CACHE = None

_DEFAULT_RECORDING_GROUP = {"allSupported": True, "includeGlobalResourceTypes": False}

_S3_DELIVERY_BUCKET_POLICY = """{{
  "Version": "2012-10-17",
  "Statement": [
    {{
      "Sid": "AWSConfigBucketPermissionsCheck",
      "Effect": "Allow",
      "Principal": {{"Service": "config.amazonaws.com"}},
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::{bucket}"
    }},
    {{
      "Sid": "AWSConfigBucketDelivery",
      "Effect": "Allow",
      "Principal": {{"Service": "config.amazonaws.com"}},
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::{bucket}/*",
      "Condition": {{"StringEquals": {{"s3:x-amz-acl": "bucket-owner-full-control"}}}}
    }}
  ]
}}"""

def _error(fn):
    """Return (code, message) of the rejection; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _retry_throttled(fn, attempts=8, base_delay=2.0, extra_codes=()):
    # Config's control plane has a very low burst limit; churning recorders/rules/
    # delivery-channels across checks reliably trips ThrottlingException. Retry those
    # transparently while re-raising any domain error a check asserts on.
    retryable = ("ThrottlingException", "TooManyRequestsException") + tuple(extra_codes)
    last = None
    for attempt in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in retryable:
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

def _ensure_config_role(ctx):
    """Resolve a role ARN usable as ConfigurationRecorder.roleARN: reuse an
    existing recorder's role, then an existing Config-trusted role, then create
    one. Skip if none is available and the caller lacks iam:CreateRole."""
    global _ROLE_ARN_CACHE
    if _ROLE_ARN_CACHE:
        return _ROLE_ARN_CACHE
    cfg = ctx.client("config")
    iam = ctx.client("iam")
    arn = None
    # 1. reuse the role of a recorder that already exists in the account.
    try:
        for r in cfg.describe_configuration_recorders().get("ConfigurationRecorders", []):
            if r.get("roleARN"):
                arn = r["roleARN"]
                break
    except Exception:
        pass
    # 2. an already-provisioned role Config can assume.
    if not arn:
        for nm in ("config-role", "AWSConfigRole", "AWSServiceRoleForConfig"):
            try:
                role = iam.get_role(RoleName=nm)["Role"]
                if _trusts_config_service(role.get("AssumeRolePolicyDocument")):
                    arn = role["Arn"]
                    break
            except Exception:
                continue
    if not arn:
        try:
            for page in iam.get_paginator("list_roles").paginate():
                for role in page.get("Roles", []):
                    if _trusts_config_service(role.get("AssumeRolePolicyDocument")):
                        arn = role["Arn"]
                        break
                if arn:
                    break
        except Exception:
            pass
    # 3. create one.
    if not arn:
        try:
            arn = iam.create_role(
                RoleName=_CONFIG_ROLE_NAME,
                AssumeRolePolicyDocument=_CONFIG_TRUST_POLICY,
                Description="sim2real behavioral fidelity probe role for AWS Config",
                Tags=[{"Key": "sim2real", "Value": "config-behavioral-role"}],
            )["Role"]["Arn"]
            try:
                iam.attach_role_policy(
                    RoleName=_CONFIG_ROLE_NAME, PolicyArn=_CONFIG_MANAGED_POLICY_ARN
                )
            except Exception:
                pass
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "EntityAlreadyExists":
                arn = iam.get_role(RoleName=_CONFIG_ROLE_NAME)["Role"]["Arn"]
            else:
                arn = None
    if not arn:
        raise AssertionError(
            "no AWS Config service role is available in this account and the caller "
            "lacks iam:CreateRole, so no configuration recorder can be created"
        )
    _ROLE_ARN_CACHE = arn
    return arn

def _clear_recorders(ctx):
    cfg = ctx.client("config")
    try:
        recs = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    except Exception:
        return
    for rec in recs:
        name = rec.get("name")
        try:
            _retry_throttled(lambda n=name: cfg.stop_configuration_recorder(ConfigurationRecorderName=n))
        except Exception:
            pass
        try:
            _retry_throttled(lambda n=name: cfg.delete_configuration_recorder(ConfigurationRecorderName=n))
        except Exception:
            pass

def _clear_delivery_channels(ctx):
    cfg = ctx.client("config")
    try:
        chans = cfg.describe_delivery_channels().get("DeliveryChannels", [])
    except Exception:
        return
    for ch in chans:
        try:
            cfg.delete_delivery_channel(DeliveryChannelName=ch.get("name"))
        except Exception:
            pass

def _recorder_status(ctx, name):
    cfg = ctx.client("config")
    statuses = cfg.describe_configuration_recorder_status(
        ConfigurationRecorderNames=[name]
    ).get("ConfigurationRecordersStatus", [])
    return statuses[0] if statuses else None

def _create_recorder(ctx, name, recording_group=None, role_arn=None):
    cfg = ctx.client("config")
    recorder = {
        "name": name,
        "roleARN": role_arn or _ensure_config_role(ctx),
        "recordingGroup": recording_group or dict(_DEFAULT_RECORDING_GROUP),
    }
    # A just-created role is not yet trusted by Config until IAM's eventual consistency
    # catches up; that surfaces as InvalidRoleException, not a transport error, so it is
    # retried against the real outcome here rather than behind a blind sleep.
    _retry_throttled(
        lambda: cfg.put_configuration_recorder(
            ConfigurationRecorder=recorder, Tags=[{"Key": "sim2real", "Value": CHECK}]
        ),
        attempts=10,
        extra_codes=("InvalidRoleException",),
    )
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=name)
        )
    )
    return name

def _start_recorder(ctx, name):
    cfg = ctx.client("config")
    _retry_throttled(lambda: cfg.start_configuration_recorder(ConfigurationRecorderName=name))
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name)
        )
    )

def _stop_recorder(ctx, name):
    cfg = ctx.client("config")
    _retry_throttled(lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name))

def _existing_delivery_bucket(ctx):
    cfg = ctx.client("config")
    try:
        channels = cfg.describe_delivery_channels().get("DeliveryChannels", [])
    except Exception:
        return None
    for ch in channels:
        if ch.get("s3BucketName"):
            return ch["s3BucketName"]
    return None

def _bucket_keys(ctx, bucket):
    s3 = ctx.client("s3")
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys

def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    try:
        for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise

def _create_delivery_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cfg-delivery-").replace("_", "-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    try:
        s3.create_bucket(**kwargs)
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code", "")
        if code not in ("AccessDenied", "AccessDeniedException"):
            raise
        # Cannot create buckets here; fall back to a bucket an existing delivery
        # channel already targets (its policy is known-good).
        reused = _existing_delivery_bucket(ctx)
        if not reused:
            raise AssertionError(
                "caller lacks s3:CreateBucket and no pre-existing Config delivery "
                "bucket is available for reuse"
            ) from exc
        return reused
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    try:
        s3.put_bucket_tagging(
            Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
        )
    except Exception:
        pass
    try:
        s3.put_bucket_policy(
            Bucket=bucket, Policy=_S3_DELIVERY_BUCKET_POLICY.format(bucket=bucket)
        )
    except Exception:
        pass
    return bucket

def _create_delivery_channel(ctx, name, bucket):
    cfg = ctx.client("config")
    channel = {"name": name, "s3BucketName": bucket}
    # The freshly-written bucket policy is eventually consistent; Config rejects a
    # delivery channel whose bucket policy has not propagated with
    # InsufficientDeliveryPolicyException.
    last = None
    for attempt in range(6):
        try:
            _retry_throttled(lambda: cfg.put_delivery_channel(DeliveryChannel=channel))
            ctx.on_cleanup(
                lambda: _retry_throttled(
                    lambda: cfg.delete_delivery_channel(DeliveryChannelName=name)
                )
            )
            return name
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "InsufficientDeliveryPolicyException":
                raise
            last = exc
            time.sleep(3 * (attempt + 1))
    raise last

CHECK = "deliver-config-snapshot"
GROUP = 'delivery-channel'
SERVICES = ['config']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """DeliverConfigSnapshot requires a running recorder and an existing
    delivery channel; on success it returns a snapshot id and updates
    DescribeDeliveryChannelStatus's snapshot delivery info."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _clear_recorders(ctx)
    _clear_delivery_channels(ctx)

    recorder_name = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, recorder_name)

    bucket = _create_delivery_bucket(ctx)
    channel_name = ctx.unique_name("sim2real-behav-cfg-channel-")
    _create_delivery_channel(ctx, channel_name, bucket)

    # Recorder exists but has never been started -> stopped state.
    code, message = _error(
        lambda: cfg.deliver_config_snapshot(deliveryChannelName=channel_name)
    )
    assert code == "NoRunningConfigurationRecorderException", code
    assert message == "Configuration recorder is turned off. Turn on configuration recorder.", message

    _start_recorder(ctx, recorder_name)
    _poll_until(
        lambda: _recorder_status(ctx, recorder_name),
        lambda s: s is not None and s.get("recording") is True,
        timeout_s=30,
        interval_s=2,
    )

    result = cfg.deliver_config_snapshot(deliveryChannelName=channel_name)
    snapshot_id = result.get("configSnapshotId")
    assert snapshot_id, result

    info = _poll_until(
        lambda: cfg.describe_delivery_channel_status(
            DeliveryChannelNames=[channel_name]
        )["DeliveryChannelsStatus"][0].get("configSnapshotDeliveryInfo", {}),
        lambda i: i.get("lastStatus") in ("SUCCESS", "FAILURE"),
        timeout_s=300,
        interval_s=5,
        description="snapshot delivery reaches a terminal lastStatus",
    )
    # A channel with a valid bucket policy and a running recorder must actually deliver; accepting
    # FAILURE here would pass a target that never delivers anything at all.
    assert info.get("lastStatus") == "SUCCESS", info

    # Terminal read at the actual destination: the object Config wrote to S3, not just
    # Config's own delivery bookkeeping: an independent read at the destination.
    keys = _poll_until(
        lambda: _bucket_keys(ctx, bucket),
        lambda ks: any(snapshot_id in k for k in ks),
        timeout_s=120,
        interval_s=5,
        description=f"the delivered snapshot {snapshot_id!r} appears in {bucket!r}",
    )
    delivered_key = next(k for k in keys if snapshot_id in k)
    body = ctx.client("s3").get_object(Bucket=bucket, Key=delivered_key)["Body"].read()
    assert body, f"the delivered snapshot object at {delivered_key!r} is empty"

    _stop_recorder(ctx, recorder_name)


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
