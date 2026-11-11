"""delivery-channel-requires-recorder."""

from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

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
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

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

_RECORDER_FIELDS = ("name", "roleARN", "recordingGroup", "recordingMode")


def _clear_recorders_and_channels(ctx):
    """Delete every customer-managed recorder and every delivery channel.

    One cleanup restores them all: recorders, then channels, then recording on the
    recorders that were recording. Returns (recorder names, channel names) deleted.
    """
    cfg = ctx.client("config")
    recording = {
        st["name"]: st.get("recording", False)
        for st in cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
    }
    recorders = [
        {k: r[k] for k in _RECORDER_FIELDS if k in r}
        for r in cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
        if not r.get("servicePrincipal")
    ]
    channels = cfg.describe_delivery_channels().get("DeliveryChannels", [])
    was_recording = [r["name"] for r in recorders if recording.get(r["name"], False)]

    for name in was_recording:
        _retry_throttled(lambda n=name: cfg.stop_configuration_recorder(ConfigurationRecorderName=n))
    for ch in channels:
        _retry_throttled(lambda n=ch["name"]: cfg.delete_delivery_channel(DeliveryChannelName=n))
    for rec in recorders:
        _retry_throttled(lambda n=rec["name"]: cfg.delete_configuration_recorder(ConfigurationRecorderName=n))

    def _restore():
        for rec in recorders:
            _retry_throttled(lambda r=rec: cfg.put_configuration_recorder(ConfigurationRecorder=r))
        # A channel can outlive its recorder, but it cannot be put back without one.
        for ch in channels if recorders else ():
            _retry_throttled(lambda c=ch: cfg.put_delivery_channel(DeliveryChannel=c))
        for name in was_recording:
            _retry_throttled(lambda n=name: cfg.start_configuration_recorder(ConfigurationRecorderName=n))

    ctx.on_cleanup(_restore)
    return [r["name"] for r in recorders], [c["name"] for c in channels]


def _create_config_role(ctx):
    """Create a role AWS Config can assume for recording; cleanup deletes it."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-behav-cfg-role-")
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_CONFIG_TRUST_POLICY,
        Description="sim2real behavioral fidelity probe role for AWS Config",
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.attach_role_policy(RoleName=name, PolicyArn=_CONFIG_MANAGED_POLICY_ARN)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=name, PolicyArn=_CONFIG_MANAGED_POLICY_ARN))
    return arn

def _put_configuration_recorder_with_retry(ctx, name, role_arn, deadline_s=90):
    # IAM is eventually consistent: a role Config was just told to trust (freshly
    # created, or freshly attached a policy) can fail to be assumable for a short
    # window afterwards. Retry only the two codes that signal exactly that.
    cfg = ctx.client("config")
    recorder = {
        "name": name,
        "roleARN": role_arn,
        "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
    }
    deadline = time.monotonic() + deadline_s
    while True:
        try:
            return _retry_throttled(
                lambda: cfg.put_configuration_recorder(ConfigurationRecorder=recorder)
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("InvalidRoleException", "InsufficientPermissionsException"):
                raise
            if time.monotonic() >= deadline:
                raise
            time.sleep(5)

def _create_delivery_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cfg-bkt-").replace("_", "-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":  # us-east-1 rejects an explicit LocationConstraint
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_policy(Bucket=bucket, Policy=_S3_DELIVERY_BUCKET_POLICY.format(bucket=bucket))
    return bucket

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

def _put_delivery_channel_with_retry(ctx, name, bucket):
    # The freshly-written bucket policy is eventually consistent; Config rejects a
    # delivery channel whose bucket policy has not propagated with
    # InsufficientDeliveryPolicyException. That is expected transient noise here,
    # not the condition under test, so retry it and nothing else.
    cfg = ctx.client("config")
    channel = {"name": name, "s3BucketName": bucket}
    last = None
    for attempt in range(6):
        try:
            return _retry_throttled(lambda: cfg.put_delivery_channel(DeliveryChannel=channel))
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "InsufficientDeliveryPolicyException":
                raise
            last = exc
            time.sleep(3 * (attempt + 1))
    raise last

CHECK = "delivery-channel-requires-recorder"
GROUP = 'delivery-channel'
SERVICES = ['config']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """With no configuration recorder, PutDeliveryChannel fails with
    NoAvailableConfigurationRecorderException and its exact message and leaves no channel; after a
    recorder is created the same call creates the channel."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    deleted, _ = _clear_recorders_and_channels(ctx)
    remaining = [
        r["name"] for r in cfg.describe_configuration_recorders()["ConfigurationRecorders"] if r["name"] in deleted
    ]
    assert remaining == [], f"expected the deleted recorders to be gone, found {remaining!r}"

    bucket = _create_delivery_bucket(ctx)
    channel_name = ctx.unique_name("sim2real-behav-cfg-channel-")

    # Break: no recorder exists -> PutDeliveryChannel must be rejected.
    code, message = _error(
        lambda: cfg.put_delivery_channel(
            DeliveryChannel={"name": channel_name, "s3BucketName": bucket}
        )
    )
    assert code == "NoAvailableConfigurationRecorderException", code
    assert message == "Configuration recorder is not available to put delivery channel.", message

    channels = cfg.describe_delivery_channels()["DeliveryChannels"]
    assert all(c["name"] != channel_name for c in channels), channels

    # Restore: create the recorder the call was missing, then retry the
    # IDENTICAL PutDeliveryChannel call.
    recorder_name = ctx.unique_name("sim2real-behav-cfg-recorder-")
    role_arn = _create_config_role(ctx)
    _put_configuration_recorder_with_retry(ctx, recorder_name, role_arn)
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=recorder_name)
        )
    )

    _put_delivery_channel_with_retry(ctx, channel_name, bucket)
    ctx.on_cleanup(
        lambda: _retry_throttled(
            lambda: cfg.delete_delivery_channel(DeliveryChannelName=channel_name)
        )
    )

    channels = cfg.describe_delivery_channels()["DeliveryChannels"]
    assert any(c["name"] == channel_name for c in channels), (
        f"expected {channel_name!r} to exist once a recorder was present, saw {channels!r}"
    )


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
