"""delivery-channel-snapshot-frequency-bounds-the-next-delivery-time."""

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_DELIVERY_BUDGET_S = 420.0
_NEXT_TIME_BUDGET_S = 300.0

#: Tolerance for clock skew between this caller and Config when bounding a reported horizon.
_CLOCK_SKEW_S = 120.0

_ONE_HOUR_S = 3600
_ONE_DAY_S = 86400

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

# Recorder transitions plus IAM propagation plus Config's low control-plane burst limit need > 300s.
_TRANSITION_BUDGET_S = 360.0

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
      "Sid": "AWSConfigBucketExistenceCheck",
      "Effect": "Allow",
      "Principal": {{"Service": "config.amazonaws.com"}},
      "Action": "s3:ListBucket",
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
    """(code, message) of the AWS error raised by fn(); raises if fn() unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("the call was expected to be rejected but it succeeded")


def _error_code_or_none(fn):
    """Error code of fn(), or None on success; for polling only, never inside an assert."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    # Config's control plane has a very low burst limit and reliably trips ThrottlingException.
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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s, interval_s=1.0, description="condition", ctx=None):
    """A bounded retry with a stated reason that RAISES on timeout - never returns its last value."""
    if ctx is not None:
        timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _trusts_config_service(doc):
    """True only if the trust policy names the EXACT config.amazonaws.com principal (a substring
    test would also match the third-party service-linked role which Config cannot assume for
    standard recording/delivery)."""
    import urllib.parse as _up

    if isinstance(doc, str):
        try:
            doc = json.loads(_up.unquote(doc))
        except (ValueError, TypeError):
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
    """Resolve the exact `sim2real-behav-config-role`, created if absent.

    A scan for any Config-trusted role could adopt a crippled one; it runs only without CreateRole.
    """
    global _ROLE_ARN_CACHE
    if _ROLE_ARN_CACHE:
        return _ROLE_ARN_CACHE
    iam = ctx.client("iam")
    arn = None
    try:
        role = iam.get_role(RoleName=_CONFIG_ROLE_NAME)["Role"]
        assert _trusts_config_service(role.get("AssumeRolePolicyDocument")), (
            f"{_CONFIG_ROLE_NAME!r} exists but does not trust config.amazonaws.com, so no recorder "
            f"built on it can record: {role!r}"
        )
        arn = role["Arn"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise
    if not arn:
        try:
            arn = iam.create_role(
                RoleName=_CONFIG_ROLE_NAME,
                AssumeRolePolicyDocument=_CONFIG_TRUST_POLICY,
                Description="sim2real behavioral fidelity probe role for AWS Config",
                Tags=[{"Key": "sim2real", "Value": "config-recorder-role"}],
            )["Role"]["Arn"]
            iam.attach_role_policy(
                RoleName=_CONFIG_ROLE_NAME, PolicyArn=_CONFIG_MANAGED_POLICY_ARN
            )
            # IAM exposes no "role is assumable" condition; _create_recorder retries instead.
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "EntityAlreadyExists":
                arn = iam.get_role(RoleName=_CONFIG_ROLE_NAME)["Role"]["Arn"]
            elif code in ("AccessDenied", "AccessDeniedException"):
                for page in iam.get_paginator("list_roles").paginate():
                    for role in page.get("Roles", []):
                        if _trusts_config_service(role.get("AssumeRolePolicyDocument")):
                            arn = role["Arn"]
                            break
                    if arn:
                        break
                if not arn:
                    raise AssertionError(
                        "no AWS Config service role is available in this account and the caller "
                        "lacks iam:CreateRole, so no configuration recorder can be created"
                    ) from exc
            else:
                raise
    _ROLE_ARN_CACHE = arn
    return arn


def _clear_recorders(ctx):
    """Remove the account's single customer-managed recorder so PutConfigurationRecorder does not
    fail with MaxNumberOfConfigurationRecordersExceededException; teardown restores it."""
    cfg = ctx.client("config")
    try:
        recs = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    except ClientError:
        return
    for rec in recs:
        name = rec.get("name")
        try:
            _retry_throttled(
                lambda n=name: cfg.stop_configuration_recorder(ConfigurationRecorderName=n)
            )
        except ClientError:
            pass
        try:
            _retry_throttled(
                lambda n=name: cfg.delete_configuration_recorder(ConfigurationRecorderName=n)
            )
        except ClientError:
            pass


def _clear_delivery_channels(ctx):
    """The delivery channel is the recorder's twin singleton (one per account per region)."""
    cfg = ctx.client("config")
    try:
        chans = cfg.describe_delivery_channels().get("DeliveryChannels", [])
    except ClientError:
        return
    for ch in chans:
        try:
            cfg.delete_delivery_channel(DeliveryChannelName=ch.get("name"))
        except ClientError:
            pass


def _empty_and_delete_bucket(ctx, bucket):
    s3 = ctx.client("s3")
    # A versioned bucket needs every version AND every delete marker removed, else delete_bucket
    # fails BucketNotEmpty; list_objects_v2 alone never sees them.
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for entry in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", [])):
                try:
                    s3.delete_object(Bucket=bucket, Key=entry["Key"], VersionId=entry["VersionId"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                try:
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
            raise
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _create_bucket(ctx, prefix, scenario):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(prefix).replace("_", "-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
        # us-east-1 rejects an explicit LocationConstraint naming itself; every other region
        # requires one.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": scenario}]}
    )
    return bucket


def _create_delivery_bucket(ctx, scenario):
    s3 = ctx.client("s3")
    bucket = _create_bucket(ctx, "sim2real-behav-cfg-delivery-", scenario)
    s3.put_bucket_policy(Bucket=bucket, Policy=_S3_DELIVERY_BUCKET_POLICY.format(bucket=bucket))
    return bucket


def _create_recorder(ctx, name, recording_group=None, role_arn=None):
    cfg = ctx.client("config")
    recorder = {
        "name": name,
        "roleARN": role_arn or _ensure_config_role(ctx),
        "recordingGroup": recording_group or dict(_DEFAULT_RECORDING_GROUP),
    }
    # PutConfigurationRecorder validates that Config can assume the role, which fails until a
    # freshly created role has propagated, so the put is retried a bounded number of times.
    last = None
    for attempt in range(8):
        try:
            _retry_throttled(lambda: cfg.put_configuration_recorder(ConfigurationRecorder=recorder))
            ctx.on_cleanup(
                lambda: _retry_throttled(
                    lambda: cfg.delete_configuration_recorder(ConfigurationRecorderName=name)
                )
            )
            return name
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("InsufficientPermissionsException", "AccessDeniedException"):
                raise
            last = exc
            time.sleep(5 * (attempt + 1))
    raise last


def _recorder_status(ctx, name):
    cfg = ctx.client("config")
    statuses = cfg.describe_configuration_recorder_status(
        ConfigurationRecorderNames=[name]
    )["ConfigurationRecordersStatus"]
    return statuses[0] if statuses else None


def _all_recorder_statuses(ctx):
    cfg = ctx.client("config")
    try:
        return [
            {
                k: s.get(k)
                for k in ("name", "recording", "lastStatus", "lastErrorCode", "lastErrorMessage")
            }
            for s in cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
        ]
    except ClientError as exc:
        return f"unreadable: {exc}"


def _start_recorder(ctx, name, register_cleanup=True):
    """Start the recorder and wait until it reports recording=True.

    Not gated on lastStatus SUCCESS: a fresh recorder stays PENDING for minutes while recording.
    """
    cfg = ctx.client("config")
    _retry_throttled(lambda: cfg.start_configuration_recorder(ConfigurationRecorderName=name))
    if register_cleanup:
        ctx.on_cleanup(
            lambda: _retry_throttled(
                lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name)
            )
        )
    _poll_until(
        lambda: _recorder_status(ctx, name),
        lambda s: s is not None and s.get("recording") is True,
        timeout_s=_TRANSITION_BUDGET_S,
        interval_s=1,
        description=f"recorder {name!r} reports recording=True",
        ctx=ctx,
    )


def _stop_recorder(ctx, name):
    cfg = ctx.client("config")
    _retry_throttled(lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name))
    _poll_until(
        lambda: _recorder_status(ctx, name),
        lambda s: s is not None and s.get("recording") is False,
        timeout_s=_TRANSITION_BUDGET_S,
        interval_s=1,
        description=f"recorder {name!r} reports recording=False",
        ctx=ctx,
    )


def _create_delivery_channel(
    ctx, name, bucket, sns_topic_arn=None, delivery_frequency=None, register_cleanup=True
):
    cfg = ctx.client("config")
    channel = {"name": name, "s3BucketName": bucket}
    if sns_topic_arn:
        channel["snsTopicARN"] = sns_topic_arn
    if delivery_frequency:
        channel["configSnapshotDeliveryProperties"] = {"deliveryFrequency": delivery_frequency}
    # The freshly-written bucket policy is eventually consistent; Config rejects a delivery channel
    # whose bucket policy has not propagated with InsufficientDeliveryPolicyException.
    last = None
    for attempt in range(8):
        try:
            _retry_throttled(lambda: cfg.put_delivery_channel(DeliveryChannel=channel))
            if register_cleanup:
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


def _start_recording(ctx, scenario, recording_group=None, sns_topic_arn=None):
    """The precondition every recording check shares: a delivery bucket carrying the Config delivery
    policy, a delivery channel, and a running recorder. Returns (recorder, channel, bucket)."""
    _clear_recorders(ctx)
    _clear_delivery_channels(ctx)
    bucket = _create_delivery_bucket(ctx, scenario)
    recorder = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, recorder, recording_group=recording_group)
    channel = ctx.unique_name("sim2real-behav-cfg-channel-")
    _create_delivery_channel(ctx, channel, bucket, sns_topic_arn=sns_topic_arn)
    _start_recorder(ctx, recorder)
    return recorder, channel, bucket


def _history_items(ctx, resource_type, resource_id):
    """Every configuration item Config holds for a resource, paginated. A
    ResourceNotDiscoveredException means Config has recorded nothing for it, which is an empty
    history rather than an error for polling purposes."""
    cfg = ctx.client("config")
    items = []
    try:
        for page in cfg.get_paginator("get_resource_config_history").paginate(
            resourceType=resource_type, resourceId=resource_id
        ):
            items.extend(page["configurationItems"])
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotDiscoveredException":
            return []
        raise
    return items


def _await_history_items(ctx, resource_type, resource_id, *, timeout_s, predicate=None,
                         description=None):
    """Poll for configuration items; on timeout, report the recorder status so a stalled recorder
    is distinguishable from an unrecorded resource."""
    predicate = predicate or (lambda items: bool(items))
    description = description or f"a configuration item for {resource_type} {resource_id!r}"
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _history_items(ctx, resource_type, resource_id)
        if predicate(last):
            return last
        time.sleep(1)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}. Recorder status: "
        f"{_all_recorder_statuses(ctx)!r}"
    )


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def _snapshot_delivery_info(ctx, channel):
    cfg = ctx.client("config")
    statuses = cfg.describe_delivery_channel_status(DeliveryChannelNames=[channel])[
        "DeliveryChannelsStatus"
    ]
    assert len(statuses) == 1, (
        f"DescribeDeliveryChannelStatus must report exactly one status for {channel!r}, got "
        f"{statuses!r}"
    )
    return statuses[0].get("configSnapshotDeliveryInfo", {})


def _stored_frequency(ctx, channel):
    cfg = ctx.client("config")
    channels = [
        c
        for c in cfg.describe_delivery_channels(DeliveryChannelNames=[channel])["DeliveryChannels"]
        if c.get("name") == channel
    ]
    assert len(channels) == 1, (
        f"DescribeDeliveryChannels must report exactly one channel named {channel!r}, got "
        f"{channels!r}"
    )
    return channels[0].get("configSnapshotDeliveryProperties", {}).get("deliveryFrequency")


def _deliver_and_settle(ctx, channel, *, why):
    """DeliverConfigSnapshot, then wait for the channel status to settle for THIS delivery and
    assert it succeeded."""
    cfg = ctx.client("config")
    # The status has no in-flight state, so freshness is anchored to the service's own prior
    # lastAttemptTime; a local-clock anchor is too coarse for two deliveries minutes apart.
    prev_attempt = _snapshot_delivery_info(ctx, channel).get("lastAttemptTime")
    if prev_attempt is not None:
        # Service timestamps can be second-granular: cross a tick so this delivery's times can be
        # strictly later than the prior delivery's.
        time.sleep(1.1)
    snapshot_id = _retry_throttled(
        lambda: cfg.deliver_config_snapshot(deliveryChannelName=channel)
    )["configSnapshotId"]
    assert snapshot_id, f"DeliverConfigSnapshot returned no configSnapshotId ({why})"

    def _settled_for_this_call(i):
        attempt = i.get("lastAttemptTime")
        if attempt is None or (prev_attempt is not None and attempt <= prev_attempt):
            return False
        return i.get("lastStatus") in ("SUCCESS", "FAILURE")

    info = _poll_until(
        lambda: _snapshot_delivery_info(ctx, channel),
        _settled_for_this_call,
        timeout_s=_DELIVERY_BUDGET_S,
        interval_s=1,
        ctx=ctx,
        description=(
            f"snapshot delivery for {channel!r} settles with a lastAttemptTime strictly after the "
            f"prior reading ({prev_attempt!r}) ({why})"
        ),
    )
    assert info.get("lastStatus") == "SUCCESS", (
        f"the snapshot delivery did not succeed ({why}): expected lastStatus SUCCESS, got "
        f"{info.get('lastStatus')!r} / {info.get('lastErrorCode')!r} "
        f"{info.get('lastErrorMessage')!r}"
    )
    return snapshot_id, info


CHECK = "delivery-channel-snapshot-frequency-bounds-the-next-delivery-time"
GROUP = "delivery-channel"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c4", "concern:negative-classes", "concern:representation",
      "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """With One_Hour, nextDeliveryTime after a snapshot delivery is in the future and at most an
    hour out; an out-of-enum frequency is refused with the stored value intact; re-putting with
    TwentyFour_Hours updates the channel in place and delivery keeps working.
    """
    _restore_config_recorder_on_teardown(ctx)
    scenario = "config-delivery-frequency-horizon"

    _clear_recorders(ctx)
    _clear_delivery_channels(ctx)
    bucket = _create_delivery_bucket(ctx, scenario)
    recorder = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, recorder)
    channel = ctx.unique_name("sim2real-behav-cfg-channel-")
    _create_delivery_channel(ctx, channel, bucket, delivery_frequency="One_Hour")
    _start_recorder(ctx, recorder)

    assert _stored_frequency(ctx, channel) == "One_Hour", (
        f"the channel must store the frequency it was created with: expected 'One_Hour', got "
        f"{_stored_frequency(ctx, channel)!r}"
    )

    # --- leg A: the One_Hour horizon, bounded against a clock read moments before ---
    _deliver_and_settle(ctx, channel, why="One_Hour leg")
    info = _poll_until(
        lambda: _snapshot_delivery_info(ctx, channel),
        lambda i: i.get("nextDeliveryTime") is not None,
        timeout_s=_NEXT_TIME_BUDGET_S,
        interval_s=1,
        ctx=ctx,
        description=(
            f"channel {channel!r} reports a configSnapshotDeliveryInfo.nextDeliveryTime after a "
            f"successful delivery"
        ),
    )
    read_at = _utc_now()
    next_hourly = info["nextDeliveryTime"]
    last_success = info.get("lastSuccessfulTime")
    assert last_success is not None, (
        f"a SUCCESS delivery must report lastSuccessfulTime; got {info!r}"
    )
    assert next_hourly > last_success, (
        f"nextDeliveryTime {next_hourly.isoformat()} must be strictly after the delivery that just "
        f"succeeded at {last_success.isoformat()}"
    )
    assert next_hourly > read_at - datetime.timedelta(seconds=_CLOCK_SKEW_S), (
        f"nextDeliveryTime {next_hourly.isoformat()} is in the past relative to the moment it was "
        f"read ({read_at.isoformat()}, +/-{_CLOCK_SKEW_S:.0f}s skew)"
    )
    hourly_horizon_s = (next_hourly - read_at).total_seconds()
    assert hourly_horizon_s <= _ONE_HOUR_S + _CLOCK_SKEW_S, (
        f"with deliveryFrequency=One_Hour the next delivery must be at most {_ONE_HOUR_S}s away "
        f"(+/-{_CLOCK_SKEW_S:.0f}s skew); Config reported {hourly_horizon_s:.0f}s "
        f"({next_hourly.isoformat()} read at {read_at.isoformat()})"
    )

    # --- an out-of-enum frequency is refused, and the stored value survives the refusal ---
    code, message = _error(
        lambda: ctx.client("config").put_delivery_channel(
            DeliveryChannel={
                "name": channel,
                "s3BucketName": bucket,
                "configSnapshotDeliveryProperties": {"deliveryFrequency": "One_Minute"},
            }
        )
    )
    assert code == "ValidationException", (
        f"a deliveryFrequency outside the modelled enum must be refused with ValidationException, "
        f"got {code!r}"
    )
    assert message == (
        "1 validation error detected: Value 'One_Minute' at "
        "'deliveryChannel.configSnapshotDeliveryProperties.deliveryFrequency' failed to satisfy "
        "constraint: Member must satisfy enum value set: "
        "[TwentyFour_Hours, Twelve_Hours, Three_Hours, Six_Hours, One_Hour]"
    ), f"unexpected message: {message!r}"
    assert _stored_frequency(ctx, channel) == "One_Hour", (
        f"the refused PutDeliveryChannel changed the stored frequency anyway: expected it to remain "
        f"'One_Hour', got {_stored_frequency(ctx, channel)!r}"
    )

    # --- leg B (control): an in-place frequency change, and delivery still works ---
    # The channel's teardown is already registered (before the recorder's stop), so the re-put
    # registers none: a second delete would run while the recorder is still recording.
    _create_delivery_channel(
        ctx, channel, bucket, delivery_frequency="TwentyFour_Hours", register_cleanup=False
    )
    assert _stored_frequency(ctx, channel) == "TwentyFour_Hours", (
        f"re-putting the channel must update deliveryFrequency in place: expected "
        f"'TwentyFour_Hours', got {_stored_frequency(ctx, channel)!r}"
    )
    channel_names = [
        c["name"] for c in ctx.client("config").describe_delivery_channels()["DeliveryChannels"]
    ]
    assert channel_names == [channel], (
        f"the delivery channel is an account/region singleton, so the re-put must not create a "
        f"second one: expected exactly [{channel!r}], got {channel_names!r}"
    )

    _, info_b = _deliver_and_settle(ctx, channel, why="TwentyFour_Hours leg")
    daily = _poll_until(
        lambda: _snapshot_delivery_info(ctx, channel).get("nextDeliveryTime"),
        lambda t: t is not None,
        timeout_s=_NEXT_TIME_BUDGET_S,
        interval_s=1,
        ctx=ctx,
        description=f"channel {channel!r} reports a nextDeliveryTime under TwentyFour_Hours",
    )
    read_at_b = _utc_now()
    daily_horizon_s = (daily - read_at_b).total_seconds()
    assert 0 < daily_horizon_s <= _ONE_DAY_S + _CLOCK_SKEW_S, (
        f"with deliveryFrequency=TwentyFour_Hours the next delivery must be in the future and at "
        f"most {_ONE_DAY_S}s away (+/-{_CLOCK_SKEW_S:.0f}s skew); Config reported "
        f"{daily_horizon_s:.0f}s ({daily.isoformat()} read at {read_at_b.isoformat()})"
    )
    assert info_b.get("lastSuccessfulTime") > last_success, (
        f"the second delivery must report a strictly later lastSuccessfulTime: "
        f"{info_b.get('lastSuccessfulTime')!r} is not after {last_success.isoformat()}"
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
