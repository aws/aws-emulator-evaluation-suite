"""configuration-recorder-lifecycle."""

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
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")

def _retry_throttled(fn, attempts=8, base_delay=2.0, extra_codes=()):
    # Config's control plane has a very low burst limit; churning recorders/rules/
    # delivery-channels across checks reliably trips ThrottlingException. Retry those
    # transparently while re-raising any domain error a check asserts on. extra_codes
    # lets a caller additionally retry a transient error bounded by a deadline (e.g. a
    # freshly-created IAM role not yet assumable by Config) instead of a fixed sleep.
    retryable = {"ThrottlingException", "TooManyRequestsException", *extra_codes}
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
                Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
            )["Role"]["Arn"]
            try:
                iam.attach_role_policy(
                    RoleName=_CONFIG_ROLE_NAME, PolicyArn=_CONFIG_MANAGED_POLICY_ARN
                )
            except Exception:
                pass
            # IAM is eventually consistent: the first callers to pass this ARN to
            # Config retry ThrottlingException/InvalidRoleException (via extra_codes)
            # on a bounded deadline instead of guessing a fixed propagation delay here.
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
    _retry_throttled(
        lambda: cfg.put_configuration_recorder(ConfigurationRecorder=recorder),
        extra_codes=("InvalidRoleException",),
    )
    ctx.on_cleanup(
        lambda: _unless_gone(lambda: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=name)
        ))
    )
    try:
        created = cfg.describe_configuration_recorders(
            ConfigurationRecorderNames=[name]
        )["ConfigurationRecorders"][0]
        arn = created.get("arn")
        if arn:
            cfg.tag_resource(
                ResourceArn=arn,
                Tags=[{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}],
            )
    except Exception:
        pass
    return name

def _start_recorder(ctx, name):
    cfg = ctx.client("config")
    _retry_throttled(lambda: cfg.start_configuration_recorder(ConfigurationRecorderName=name))
    ctx.on_cleanup(
        lambda: _unless_gone(lambda: _retry_throttled(
            lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name)
        ))
    )

def _unless_gone(fn):
    """Teardown of a recorder the body may already have deleted: only its absence is tolerated."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchConfigurationRecorderException":
            raise

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
    # S3's own CreateBucket contract, not a check region pin: us-east-1 is the one
    # region that rejects an explicit LocationConstraint matching the default region.
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
        s3.put_bucket_policy(
            Bucket=bucket, Policy=_S3_DELIVERY_BUCKET_POLICY.format(bucket=bucket)
        )
    except Exception:
        pass
    try:
        s3.put_bucket_tagging(
            Bucket=bucket,
            Tagging={"TagSet": [{"Key": "env", "Value": "test"}, {"Key": "owner", "Value": "fidelity"}]},
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

CHECK = "configuration-recorder-lifecycle"
GROUP = 'configuration-recorder'
SERVICES = ['config']

@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """PutConfigurationRecorder validates recordingGroup and the recorder
    transitions stopped(created) -> recording=true -> recording=false, and is
    deletable once stopped."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    _clear_recorders(ctx)
    name = ctx.unique_name("sim2real-behav-cfg-recorder-")
    role_arn = _ensure_config_role(ctx)

    # Invalid recording group: allSupported=True combined with an explicit
    # resourceTypes list must be rejected before any recorder is created.
    bad_group = {"allSupported": True, "resourceTypes": ["AWS::EC2::Instance"]}
    # retry_throttled re-raises the InvalidRecordingGroupException
    # we expect while retrying Config's low-burst-limit ThrottlingException and (via
    # extra_codes) a freshly-created role not yet assumable by Config, so neither a
    # transient throttle nor IAM propagation can mask the validation error we assert.
    code, message = _error(
        lambda: _retry_throttled(
            lambda: cfg.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": name,
                    "roleARN": role_arn,
                    "recordingGroup": bad_group,
                }
            ),
            extra_codes=("InvalidRoleException",),
        )
    )
    assert code == "InvalidRecordingGroupException", code
    assert message == "The recording group provided is not valid", message

    _create_recorder(ctx, name)

    recorders = cfg.describe_configuration_recorders()["ConfigurationRecorders"]
    assert any(r["name"] == name for r in recorders), recorders

    status = _recorder_status(ctx, name)
    assert status is not None and status.get("recording") is False, status

    # Recorder cannot start without a delivery channel (see dedicated
    # overly-permissive check) -- provide one here to drive the real
    # recording=true -> false transition.
    bucket = _create_delivery_bucket(ctx)
    channel_name = ctx.unique_name("sim2real-behav-cfg-channel-")
    _create_delivery_channel(ctx, channel_name, bucket)

    _start_recorder(ctx, name)
    started = _poll_until(
        lambda: _recorder_status(ctx, name),
        lambda s: s is not None and s.get("recording") is True,
        timeout_s=30,
        interval_s=2,
    )
    assert started.get("recording") is True, started

    _stop_recorder(ctx, name)
    stopped = _poll_until(
        lambda: _recorder_status(ctx, name),
        lambda s: s is not None and s.get("recording") is False,
        timeout_s=30,
        interval_s=2,
    )
    assert stopped.get("recording") is False, stopped

    cfg.delete_configuration_recorder(ConfigurationRecorderName=name)
    remaining = cfg.describe_configuration_recorders()["ConfigurationRecorders"]
    assert all(r["name"] != name for r in remaining), remaining

    # Deleted must mean gone, not just absent from the unfiltered list: a named lookup
    # on the dead id is the specific not-found code, and a mutation on it fails too.
    not_found = "The name of the configuration recorder you entered cannot be found. Verify the configuration recorder name, and try again."
    code, message = _error(
        lambda: cfg.describe_configuration_recorders(ConfigurationRecorderNames=[name])
    )
    assert code == "NoSuchConfigurationRecorderException", code
    assert message == not_found, message

    code, message = _error(
        lambda: cfg.start_configuration_recorder(ConfigurationRecorderName=name)
    )
    assert code == "NoSuchConfigurationRecorderException", code
    assert message == not_found, message


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
