"""recorder-status-timestamps-bracket-a-real-start-stop-restart."""

from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

#: Allowance for clock skew between this caller and the Config service when bracketing a timestamp
#: against locally measured wall-clock; a tolerance, not a deadline.
_CLOCK_SKEW_S = 120.0

#: Consecutive status reads taken with no transition in between, for the freeze detector.
_FREEZE_READS = 3

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

# Per-transition bound: IAM propagation and Config's low burst limit make transitions slow.
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


def _error_code(fn):
    """The AWS error code raised by fn(); an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError("the call was expected to be rejected but it succeeded")


def _error_code_or_none(fn):
    """For polling a condition expressed as an error code; returns None on success."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return None


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    # Config's control plane has a very low burst limit; churning recorders/rules/delivery-channels
    # across checks reliably trips ThrottlingException. Retry those transparently while re-raising
    # any domain error a check asserts on.
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
    """Resolve the exact `sim2real-behav-config-role`, created if absent. A scan for any role
    trusting config.amazonaws.com could adopt an unsuitable role, so it runs only when the caller
    lacks iam:CreateRole."""
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
            # No API reports when a role becomes assumable; the retry in _create_recorder guards it.
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
    """Only one customer-managed recorder exists per account and region, so a leftover one makes
    PutConfigurationRecorder fail with MaxNumberOfConfigurationRecordersExceededException."""
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
    # freshly created role has propagated.
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
            if code not in (
                "InsufficientPermissionsException", "AccessDeniedException", "InvalidRoleException"
            ):
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

    Not gated on lastStatus == 'SUCCESS': a fresh recorder can sit at PENDING for minutes while
    already producing configuration items."""
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


def _create_delivery_channel(ctx, name, bucket, sns_topic_arn=None, delivery_frequency=None):
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
    """Poll for configuration items and, on timeout, report the RECORDER's own status alongside the
    empty result: without that, a stalled recorder and a genuinely unrecorded resource produce the
    identical message and neither is diagnosable."""
    predicate = predicate or (lambda items: bool(items))
    description = description or f"a configuration item for {resource_type} {resource_id!r}"
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _history_items(ctx, resource_type, resource_id)
        if predicate(last):
            return last
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}. Recorder status: "
        f"{_all_recorder_statuses(ctx)!r}"
    )


def _utc_now():
    return datetime.datetime.now(datetime.timezone.utc)


def _transition_fields(status):
    return status.get("lastStartTime"), status.get("lastStopTime")


CHECK = "recorder-status-timestamps-bracket-a-real-start-stop-restart"
GROUP = "configuration-recorder"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """Recorder status lastStartTime/lastStopTime fall inside the window around each Start/Stop
    call, a stop does not rewrite the start, a restart moves only lastStartTime forward, and idle
    reads change neither.

    Reference: https://docs.aws.amazon.com/config/latest/APIReference/API_ConfigurationRecorderStatus.html
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    scenario = "config-recorder-status-timestamps"

    _clear_recorders(ctx)
    _clear_delivery_channels(ctx)
    bucket = _create_delivery_bucket(ctx, scenario)
    recorder = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, recorder)
    channel = ctx.unique_name("sim2real-behav-cfg-channel-")
    _create_delivery_channel(ctx, channel, bucket)

    # A recorder that has never run has no transition history.
    pre = _recorder_status(ctx, recorder)
    assert pre is not None, (
        f"DescribeConfigurationRecorderStatus returned no entry for the recorder that was just "
        f"created: expected one status for {recorder!r}, got {_all_recorder_statuses(ctx)!r}"
    )
    assert pre.get("recording") is False, (
        f"a recorder that was created but never started must report recording=False, got "
        f"{pre.get('recording')!r} for {recorder!r}"
    )
    assert pre.get("lastStartTime") is None and pre.get("lastStopTime") is None, (
        f"a recorder that has never been started or stopped must report neither lastStartTime nor "
        f"lastStopTime; expected (None, None), got {_transition_fields(pre)!r}"
    )

    # The start is bracketed by locally measured wall-clock.
    before_start = _utc_now()
    _start_recorder(ctx, recorder)
    after_start = _utc_now()
    s1 = _recorder_status(ctx, recorder)
    start_1, stop_1 = _transition_fields(s1)
    assert start_1 is not None, (
        f"a recorder reporting recording=True must report a lastStartTime; got {s1!r}"
    )
    lower = before_start - datetime.timedelta(seconds=_CLOCK_SKEW_S)
    upper = after_start + datetime.timedelta(seconds=_CLOCK_SKEW_S)
    assert lower <= start_1 <= upper, (
        f"lastStartTime {start_1.isoformat()} is outside the window this check measured around its "
        f"own StartConfigurationRecorder call ({before_start.isoformat()} .. "
        f"{after_start.isoformat()}, +/-{_CLOCK_SKEW_S:.0f}s skew)"
    )
    assert stop_1 is None, (
        f"a recorder that has been started but never stopped must report no lastStopTime, got "
        f"{stop_1!r}"
    )

    # Idle reads must not advance the transition log.
    frozen = []
    for _ in range(_FREEZE_READS):
        # A fixed gap is intended: time passing without a transition must change nothing.
        time.sleep(1.1)
        frozen.append(_transition_fields(_recorder_status(ctx, recorder)))
    assert frozen == [(start_1, None)] * _FREEZE_READS, (
        f"{_FREEZE_READS} consecutive status reads with no transition in between changed the "
        f"transition log: expected {[(start_1, None)] * _FREEZE_READS!r}, got {frozen!r}"
    )

    # The stop is bracketed and does not rewrite the start.
    before_stop = _utc_now()
    _stop_recorder(ctx, recorder)
    after_stop = _utc_now()
    s2 = _recorder_status(ctx, recorder)
    start_2, stop_2 = _transition_fields(s2)
    assert stop_2 is not None, (
        f"a recorder reporting recording=False after a stop must report a lastStopTime; got {s2!r}"
    )
    assert (before_stop - datetime.timedelta(seconds=_CLOCK_SKEW_S)) <= stop_2 <= (
        after_stop + datetime.timedelta(seconds=_CLOCK_SKEW_S)
    ), (
        f"lastStopTime {stop_2.isoformat()} is outside the window measured around this check's own "
        f"StopConfigurationRecorder call ({before_stop.isoformat()} .. {after_stop.isoformat()}, "
        f"+/-{_CLOCK_SKEW_S:.0f}s skew)"
    )
    assert stop_2 > start_1, (
        f"lastStopTime {stop_2.isoformat()} must be strictly after the lastStartTime it followed "
        f"({start_1.isoformat()})"
    )
    assert start_2 == start_1, (
        f"stopping the recorder rewrote lastStartTime: expected it to stay {start_1.isoformat()}, "
        f"got {start_2!r}"
    )

    # A restart moves only lastStartTime, and only forwards. Status timestamps can be
    # second-granular, so the restart crosses a tick after the stop.
    time.sleep(1.1)
    before_restart = _utc_now()
    _start_recorder(ctx, recorder, register_cleanup=False)
    after_restart = _utc_now()
    s3 = _recorder_status(ctx, recorder)
    start_3, stop_3 = _transition_fields(s3)
    assert start_3 is not None and start_3 > start_1, (
        f"a second start must move lastStartTime strictly forward: expected something later than "
        f"{start_1.isoformat()}, got {start_3!r}"
    )
    assert (before_restart - datetime.timedelta(seconds=_CLOCK_SKEW_S)) <= start_3 <= (
        after_restart + datetime.timedelta(seconds=_CLOCK_SKEW_S)
    ), (
        f"the restarted lastStartTime {start_3.isoformat()} is outside the window measured around "
        f"the second StartConfigurationRecorder call ({before_restart.isoformat()} .. "
        f"{after_restart.isoformat()}, +/-{_CLOCK_SKEW_S:.0f}s skew)"
    )
    assert stop_3 == stop_2, (
        f"restarting the recorder rewrote or cleared lastStopTime: expected it to stay "
        f"{stop_2.isoformat()}, got {stop_3!r}"
    )
    assert start_3 > stop_3, (
        f"after a stop and a restart the recorder must report lastStartTime "
        f"({start_3.isoformat()}) strictly later than lastStopTime ({stop_3.isoformat()})"
    )

    # The same transition log through two other read operations.
    unfiltered = [
        s
        for s in cfg.describe_configuration_recorder_status()["ConfigurationRecordersStatus"]
        if s.get("name") == recorder
    ]
    assert len(unfiltered) == 1, (
        f"the unfiltered DescribeConfigurationRecorderStatus must report exactly one entry for "
        f"{recorder!r}, got {len(unfiltered)}: {_all_recorder_statuses(ctx)!r}"
    )
    assert _transition_fields(unfiltered[0]) == (start_3, stop_3), (
        f"the unfiltered status read disagrees with the name-filtered one about the transition log: "
        f"expected {(start_3, stop_3)!r}, got {_transition_fields(unfiltered[0])!r}"
    )
    summaries = cfg.list_configuration_recorders()["ConfigurationRecorderSummaries"]
    mine = [s for s in summaries if s.get("name") == recorder]
    assert len(mine) == 1, (
        f"ListConfigurationRecorders must report exactly one summary for {recorder!r}, got "
        f"{[s.get('name') for s in summaries]!r}"
    )
    assert mine[0].get("servicePrincipal") is None, (
        f"a customer-managed recorder must carry no servicePrincipal, got "
        f"{mine[0].get('servicePrincipal')!r} for {recorder!r}"
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
