"""get-resource-config-history-window-and-forward-order-select-real-items."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_CI_BUDGET_S = 480.0
# A change-driven configuration item can lag the change by several minutes.
_SECOND_CI_BUDGET_S = 600.0
_VERSIONING_BUDGET_S = 120.0
# Comparison passes, each over one unchanged history.
_SNAPSHOT_PASSES = 5

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


def _error_code(fn):
    """The AWS error code raised by fn(); raises if fn() unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
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
            # IAM exposes no "role is assumable" condition; _create_recorder retries until it is.
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
    """Poll for configuration items; on timeout, report the recorder status so a stalled recorder
    is distinguishable from an unrecorded resource."""
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


def _history_with(ctx, resource_type, resource_id, **kwargs):
    """GetResourceConfigHistory walked to exhaustion by hand, so nextToken behaviour is checked."""
    cfg = ctx.client("config")
    items, token = [], None
    while True:
        params = dict(resourceType=resource_type, resourceId=resource_id, **kwargs)
        if token:
            params["nextToken"] = token
        resp = cfg.get_resource_config_history(**params)
        items.extend(resp["configurationItems"])
        token = resp.get("nextToken")
        if not token:
            return items


def _times(items):
    return [i["configurationItemCaptureTime"] for i in items]


def _canonical(value):
    """A JSON value with object keys and array members in one order: Config documents neither the
    key order of a configuration nor the order of its lists."""
    if isinstance(value, dict):
        return {k: _canonical(v) for k, v in sorted(value.items())}
    if isinstance(value, list):
        return sorted((_canonical(v) for v in value), key=lambda v: json.dumps(v, sort_keys=True))
    return value


def _configuration(item):
    """An item's configuration, parsed and in canonical order."""
    raw = item.get("configuration")
    return _canonical(json.loads(raw)) if raw else raw


def _recorded(items):
    """What each item recorded: its capture time and configuration."""
    return [(i["configurationItemCaptureTime"], _configuration(i)) for i in items]


def _widest_gap_midpoint(times_desc):
    """The midpoint of the largest gap between two adjacent capture times.

    A midpoint keeps the window assertions independent of earlierTime/laterTime inclusivity.
    """
    ordered = sorted(times_desc)
    gaps = [
        (ordered[i + 1] - ordered[i], ordered[i], ordered[i + 1]) for i in range(len(ordered) - 1)
    ]
    widest = max(gaps, key=lambda g: g[0])
    return widest[1] + (widest[2] - widest[1]) / 2


CHECK = "get-resource-config-history-window-and-forward-order-select-real-items"
GROUP = "ordering"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """Over a two-change bucket history, Forward is exactly Reverse inverted, earlierTime/laterTime
    split the items at an observed pivot, a limit=1 walk visits each item once, and
    BatchGetResourceConfig returns the newest item.
    """
    _restore_config_recorder_on_teardown(ctx)
    s3 = ctx.client("s3")
    scenario = "config-history-window-and-order"

    _start_recording(ctx, scenario)

    bucket = _create_bucket(ctx, "sim2real-behav-cfg-hist-", scenario)
    _await_history_items(
        ctx, "AWS::S3::Bucket", bucket, timeout_s=_CI_BUDGET_S,
        description=f"the first configuration item for bucket {bucket!r}",
    )

    # --- a second, unmistakable change to the SAME resource, made out of band ---
    # Capture times can be second-granular: cross a tick so the two items' times differ.
    time.sleep(1.1)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    live = _poll_until(
        lambda: s3.get_bucket_versioning(Bucket=bucket).get("Status"),
        lambda v: v == "Enabled",
        timeout_s=_VERSIONING_BUDGET_S,
        interval_s=1,
        description=f"bucket {bucket!r} reads back versioning Enabled",
        ctx=ctx,
    )
    assert live == "Enabled", f"expected the bucket to read back Enabled versioning, got {live!r}"

    reverse = _await_history_items(
        ctx,
        "AWS::S3::Bucket",
        bucket,
        predicate=lambda items: len(items) >= 2,
        timeout_s=_SECOND_CI_BUDGET_S,
        description=f"at least two configuration items for bucket {bucket!r} after two changes",
    )

    # Config can record a further item for the bucket while the comparisons run. A pass counts
    # only when the history read after it equals the one it compared, so every compared read sees
    # one history.
    for _ in range(_SNAPSHOT_PASSES):
        try:
            _assert_history_claims(ctx, bucket, reverse)
            failure = None
        except AssertionError as exc:
            failure = exc
        closing = _history_items(ctx, "AWS::S3::Bucket", bucket)
        if _recorded(closing) == _recorded(reverse):
            if failure is not None:
                raise failure
            return
        reverse = closing
        time.sleep(1)
    raise AssertionError(
        f"the configuration history of bucket {bucket!r} changed during each of "
        f"{_SNAPSHOT_PASSES} comparison passes; last: {_times(reverse)!r}"
    )


def _assert_history_claims(ctx, bucket, reverse):
    """The ordering, window, paging and BatchGet claims over one read of the bucket's history."""
    cfg = ctx.client("config")
    reverse_times = _times(reverse)
    assert len(reverse) >= 2, (
        f"the window and ordering claims need at least two items; got {len(reverse)}: "
        f"{reverse_times!r}"
    )
    assert reverse_times == sorted(reverse_times, reverse=True), (
        f"the documented default order is reverse-chronological; got {reverse_times!r}"
    )

    # --- Forward must be the same items, inverted ---
    explicit_reverse = _times(
        _history_with(ctx, "AWS::S3::Bucket", bucket, chronologicalOrder="Reverse")
    )
    forward = _times(_history_with(ctx, "AWS::S3::Bucket", bucket, chronologicalOrder="Forward"))
    assert set(forward) >= set(reverse_times), (
        f"chronologicalOrder=Forward dropped items the default order returned: forward={forward!r} "
        f"is missing {sorted(set(reverse_times) - set(forward))!r}"
    )
    assert forward == sorted(forward), (
        f"chronologicalOrder=Forward must return capture times ascending; got {forward!r}"
    )
    assert list(reversed(forward)) == explicit_reverse, (
        f"Forward and Reverse must be exact inversions of one another over the same items: "
        f"reversed(Forward)={list(reversed(forward))!r} != Reverse={explicit_reverse!r}"
    )

    # --- the window, pivoted on a midpoint derived from the run's own timestamps ---
    pivot = _widest_gap_midpoint(reverse_times)
    older = sorted(t for t in reverse_times if t < pivot)
    newer = sorted(t for t in reverse_times if t > pivot)
    assert older and newer, (
        f"the derived pivot {pivot.isoformat()} must fall strictly between two observed capture "
        f"times; got older={older!r} newer={newer!r} from {reverse_times!r}"
    )

    after_pivot = _times(_history_with(ctx, "AWS::S3::Bucket", bucket, earlierTime=pivot))
    assert all(t >= pivot for t in after_pivot), (
        f"earlierTime={pivot.isoformat()} must exclude every item captured before it; got "
        f"{sorted(t for t in after_pivot if t < pivot)!r} inside {after_pivot!r}"
    )
    assert set(newer) <= set(after_pivot), (
        f"earlierTime={pivot.isoformat()} dropped items it must return: {sorted(set(newer) - set(after_pivot))!r}"
    )

    before_pivot = _times(_history_with(ctx, "AWS::S3::Bucket", bucket, laterTime=pivot))
    assert all(t <= pivot for t in before_pivot), (
        f"laterTime={pivot.isoformat()} must exclude every item captured after it; got "
        f"{sorted(t for t in before_pivot if t > pivot)!r} inside {before_pivot!r}"
    )
    assert set(older) <= set(before_pivot), (
        f"laterTime={pivot.isoformat()} dropped items it must return: {sorted(set(older) - set(before_pivot))!r}"
    )
    assert not (set(after_pivot) & set(before_pivot)), (
        f"the two complementary windows around {pivot.isoformat()} overlap: "
        f"{sorted(set(after_pivot) & set(before_pivot))!r}"
    )

    # --- a one-item-per-page walk must visit every item exactly once ---
    paged = _times(_history_with(ctx, "AWS::S3::Bucket", bucket, limit=1))
    assert len(paged) == len(set(paged)), (
        f"a limit=1 walk returned duplicates, so nextToken restarts or repeats the scan: {paged!r}"
    )
    assert set(reverse_times) <= set(paged), (
        f"a limit=1 walk lost items the unpaginated read returned: "
        f"{sorted(set(reverse_times) - set(paged))!r}"
    )

    # --- independent read at the destination, through a different operation ---
    newest_item = _history_with(ctx, "AWS::S3::Bucket", bucket, chronologicalOrder="Reverse")[0]
    base = cfg.batch_get_resource_config(
        resourceKeys=[{"resourceType": "AWS::S3::Bucket", "resourceId": bucket}]
    )["baseConfigurationItems"]
    assert [i["resourceId"] for i in base] == [bucket], (
        f"BatchGetResourceConfig must return exactly the recorded bucket, got "
        f"{[i.get('resourceId') for i in base]!r}"
    )
    assert base[0]["configurationItemCaptureTime"] == newest_item["configurationItemCaptureTime"], (
        f"BatchGetResourceConfig returned an item captured at "
        f"{base[0]['configurationItemCaptureTime']!r}, not the newest history item's "
        f"{newest_item['configurationItemCaptureTime']!r}"
    )
    assert _configuration(base[0]) == _configuration(newest_item), (
        f"the two read paths disagree about the newest recording of {bucket!r}: "
        f"{base[0]['configuration']!r} != {newest_item['configuration']!r}"
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
