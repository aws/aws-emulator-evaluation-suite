"""delivery-channel-delete-blocked-while-recording."""

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
    """Return (code, HTTP status, message) of the rejection; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        return err.get("Code"), status, err.get("Message") or ""
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")

def _unless_gone(fn):
    """Teardown step that is a no-op once the check itself already removed the resource."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in ("NoSuchConfigurationRecorderException", "NoSuchDeliveryChannelException"):
            raise

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

def _create_config_role(ctx):
    """A check-owned role Config can assume (AWS_ConfigRole attached), deleted at teardown."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-config-role-")
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=_CONFIG_TRUST_POLICY,
        Description="sim2real behavioral fidelity probe role for AWS Config",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

    def _delete_role():
        for op in (
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=_CONFIG_MANAGED_POLICY_ARN),
            lambda: iam.delete_role(RoleName=role_name),
        ):
            try:
                op()
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
                    raise

    ctx.on_cleanup(_delete_role)
    iam.attach_role_policy(RoleName=role_name, PolicyArn=_CONFIG_MANAGED_POLICY_ARN)
    return arn

_RECORDER_FIELDS = ("name", "roleARN", "recordingGroup", "recordingMode")
_CHANNEL_FIELDS = (
    "name", "s3BucketName", "s3KeyPrefix", "s3KmsKeyArn", "snsTopicARN",
    "configSnapshotDeliveryProperties",
)


def _snapshot_singletons(ctx):
    """The account's customer-managed recorder (config and recording flag) and delivery channel.
    Both are per-region singletons, so the check reuses them and puts them back exactly.
    Service-linked recorders (servicePrincipal set) are not the customer's and are ignored."""
    cfg = ctx.client("config")
    recs = [
        r
        for r in _retry_throttled(lambda: cfg.describe_configuration_recorders()).get(
            "ConfigurationRecorders", []
        )
        if not r.get("servicePrincipal")
    ]
    recorder = {k: recs[0][k] for k in _RECORDER_FIELDS if k in recs[0]} if recs else None
    recording = False
    if recorder:
        status = _recorder_status(ctx, recorder["name"])
        recording = bool(status and status.get("recording"))
    chans = _retry_throttled(lambda: cfg.describe_delivery_channels()).get("DeliveryChannels", [])
    channel = {k: chans[0][k] for k in _CHANNEL_FIELDS if k in chans[0]} if chans else None
    return {"recorder": recorder, "recording": recording, "channel": channel}


def _gone_ok(fn):
    """Teardown step that is a no-op once the resource is already gone."""
    try:
        fn()
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        if code not in ("NoSuchConfigurationRecorderException", "NoSuchDeliveryChannelException"):
            raise


def _set_recording(ctx, name, recording):
    """Start or stop the recorder only if its recording flag differs, then wait for it."""
    cfg = ctx.client("config")
    status = _recorder_status(ctx, name)
    if bool(status and status.get("recording")) == recording:
        return
    if recording:
        _retry_throttled(lambda: cfg.start_configuration_recorder(ConfigurationRecorderName=name))
    else:
        _retry_throttled(lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name))
    _poll_until(
        lambda: _recorder_status(ctx, name),
        lambda s: s is not None and bool(s.get("recording")) == recording,
        timeout_s=90,
        interval_s=2,
        description=f"recorder {name!r} reports recording={recording}",
    )


def _teardown_singletons(ctx, snap, created):
    """Stop and remove only what the check created, then put the prior recorder and channel back
    with their prior recording state. The order is forced by Config: a channel cannot be deleted
    under a running recorder, and a channel can only be put while some recorder exists."""
    cfg = ctx.client("config")
    prior_rec, prior_chan = snap["recorder"], snap["channel"]
    if created.get("recorder"):
        _gone_ok(lambda: _set_recording(ctx, created["recorder"], False))
    if prior_rec and (not snap["recording"] or created.get("channel")):
        _set_recording(ctx, prior_rec["name"], False)
    if prior_rec:
        _retry_throttled(lambda: cfg.put_configuration_recorder(ConfigurationRecorder=prior_rec))
    if created.get("channel"):
        _gone_ok(lambda: _retry_throttled(
            lambda: cfg.delete_delivery_channel(DeliveryChannelName=created["channel"])))
    if prior_chan:
        _retry_throttled(lambda: cfg.put_delivery_channel(DeliveryChannel=prior_chan))
    if created.get("recorder"):
        _gone_ok(lambda: _retry_throttled(
            lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=created["recorder"])))
    if prior_rec and snap["recording"]:
        _set_recording(ctx, prior_rec["name"], True)


def _recorder_status(ctx, name):
    cfg = ctx.client("config")
    statuses = cfg.describe_configuration_recorder_status(
        ConfigurationRecorderNames=[name]
    ).get("ConfigurationRecordersStatus", [])
    return statuses[0] if statuses else None

def _retry_on(fn, error_codes, *, timeout_s=60.0, interval_s=5.0):
    # IAM is eventually consistent: a role created moments ago can still be
    # rejected as invalid by Config's pass-role validation. Bound the wait on
    # that specific code instead of guessing a fixed delay.
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in error_codes or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

def _create_recorder(ctx, name, recording_group=None, role_arn=None, register_cleanup=True):
    cfg = ctx.client("config")
    recorder = {
        "name": name,
        "roleARN": role_arn or _create_config_role(ctx),
        "recordingGroup": recording_group or dict(_DEFAULT_RECORDING_GROUP),
    }
    _retry_on(
        lambda: _retry_throttled(
            lambda: cfg.put_configuration_recorder(ConfigurationRecorder=recorder)
        ),
        ("InvalidRoleException",),
    )
    if register_cleanup:
        ctx.on_cleanup(
            lambda: _unless_gone(
                lambda: _retry_throttled(
                    lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=name)
                )
            )
        )
    return name

def _empty_and_delete_bucket(ctx, bucket):
    """Teardown: only NoSuchBucket (already gone) is tolerated."""
    s3 = ctx.client("s3")
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchBucket":
            raise

def _create_delivery_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-cfg-delivery-").replace("_", "-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket,
        Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}, {"Key": "sim2real-check", "Value": CHECK}]},
    )
    s3.put_bucket_policy(Bucket=bucket, Policy=_S3_DELIVERY_BUCKET_POLICY.format(bucket=bucket))
    return bucket

def _create_delivery_channel(ctx, name, bucket, register_cleanup=True):
    cfg = ctx.client("config")
    channel = {"name": name, "s3BucketName": bucket}
    # The freshly-written bucket policy is eventually consistent; Config rejects a
    # delivery channel whose bucket policy has not propagated with
    # InsufficientDeliveryPolicyException.
    last = None
    for attempt in range(6):
        try:
            _retry_throttled(lambda: cfg.put_delivery_channel(DeliveryChannel=channel))
            if register_cleanup:
                ctx.on_cleanup(
                    lambda: _unless_gone(
                        lambda: _retry_throttled(
                            lambda: cfg.delete_delivery_channel(DeliveryChannelName=name)
                        )
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

CHECK = "delivery-channel-delete-blocked-while-recording"
GROUP = 'delivery-channel'
SERVICES = ['config']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """DeleteDeliveryChannel on the only channel of a running recorder fails with HTTP 400
    LastDeliveryChannelDeleteFailedException and its exact message and keeps the channel; after the
    recorder stops the delete succeeds and the channel answers NoSuchDeliveryChannelException."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    # Account singletons: run the scenario on the account's own recorder and channel when they
    # exist, and put them back exactly (config and recording state) at cleanup.
    snap = _snapshot_singletons(ctx)
    created = {}
    if snap["channel"]:
        channel_name = snap["channel"]["name"]
    else:
        bucket = _create_delivery_bucket(ctx)
        channel_name = ctx.unique_name("sim2real-behav-cfg-channel-")
    ctx.on_cleanup(lambda: _teardown_singletons(ctx, snap, created))

    if snap["recorder"]:
        recorder_name = snap["recorder"]["name"]
    else:
        recorder_name = ctx.unique_name("sim2real-behav-cfg-recorder-")
        _create_recorder(ctx, recorder_name, register_cleanup=False)
        created["recorder"] = recorder_name
    if not snap["channel"]:
        _create_delivery_channel(ctx, channel_name, bucket, register_cleanup=False)
        created["channel"] = channel_name
    _set_recording(ctx, recorder_name, True)

    code, status, message = _error(
        lambda: cfg.delete_delivery_channel(DeliveryChannelName=channel_name)
    )
    assert code == "LastDeliveryChannelDeleteFailedException", code
    assert status == 400, f"expected HTTP 400 for the blocked delete, got {status!r}"
    expected_message = f"Failed to delete last specified delivery channel with name '{channel_name}', because there is a running configuration recorder."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"

    channels = cfg.describe_delivery_channels()["DeliveryChannels"]
    assert any(c["name"] == channel_name for c in channels), channels

    # Restore: stop the recorder that was the sole reason the delete was
    # blocked, then demand the identical call now succeeds.
    _set_recording(ctx, recorder_name, False)

    cfg.delete_delivery_channel(DeliveryChannelName=channel_name)
    remaining = cfg.describe_delivery_channels()["DeliveryChannels"]
    assert all(c["name"] != channel_name for c in remaining), remaining

    # Gone and unusable: the by-name read and a second delete are both refused.
    code, status, message = _error(
        lambda: cfg.describe_delivery_channels(DeliveryChannelNames=[channel_name])
    )
    assert code == "NoSuchDeliveryChannelException", code
    assert status == 400, f"expected HTTP 400 describing the deleted channel, got {status!r}"
    expected_message = f"Cannot find delivery channel with specified name '{channel_name}'."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"
    code, status, message = _error(lambda: cfg.delete_delivery_channel(DeliveryChannelName=channel_name))
    assert code == "NoSuchDeliveryChannelException", code
    assert status == 400, f"expected HTTP 400 deleting the deleted channel, got {status!r}"
    expected_message = f"Cannot find delivery channel with specified name '{channel_name}'."
    assert message == expected_message, f"expected the message {expected_message!r}, got {message!r}"


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
