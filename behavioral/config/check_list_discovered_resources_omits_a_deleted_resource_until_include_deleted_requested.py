"""list-discovered-resources-omits-a-deleted-resource-until-include-deleted-requested."""

# Mutates the account-global configuration recorder and delivery channel (one per account and Region).
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_CI_BUDGET_S = 480.0
_DELETION_CI_BUDGET_S = 600.0
_BUCKET_GONE_BUDGET_S = 180.0

#: Consecutive listings taken with nothing mutated in between.
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

# Recorder transitions plus IAM propagation under Config's low control-plane burst limit are slow.
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
    """Return the AWS error code raised by fn(); raise if fn() unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError("the call was expected to be rejected but it succeeded")


_CALL_SUCCEEDED = "<call succeeded>"


def _error_code_or_success(fn):
    """Return fn()'s (error code, message), or (_CALL_SUCCEEDED, None) (no code can equal it) on success."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    return _CALL_SUCCEEDED, None


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    # Config's control plane has a very low burst limit; retry throttling, re-raise anything else.
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
    """Poll probe() until predicate holds; raise on timeout."""
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
    """True only if the trust policy names the exact config.amazonaws.com principal; a substring
    test would also match service-linked principals Config cannot assume for recording."""
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
    """Return the fixed recorder role, creating it if absent.

    A scan for any role trusting Config could adopt another role that records nothing, so it is
    only a fallback when the caller lacks iam:CreateRole."""
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
            # IAM exposes no assumability signal; _create_recorder retries through it.
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
    """Remove the account's single configuration recorder so PutConfigurationRecorder cannot fail
    with MaxNumberOfConfigurationRecordersExceededException; this is a precondition."""
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
    """Remove the account's single delivery channel (one per account and Region)."""
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
        # requires one. Region comes from ctx, never a literal.
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
    # PutConfigurationRecorder validates that Config can assume the role, which fails until a new
    # role has propagated.
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
    """Start the recorder and wait for recording=True.

    Not gated on lastStatus == 'SUCCESS': it can sit at PENDING for minutes while items flow."""
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
    """Set up a delivery bucket, delivery channel and running recorder; return (recorder, channel,
    bucket)."""
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
    """Every configuration item for a resource, paginated; ResourceNotDiscoveredException is empty."""
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
    """Poll for configuration items; on timeout include recorder status so a stalled recorder is
    distinguishable from an unrecorded resource."""
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


def _discovered(ctx, resource_type, resource_ids, *, include_deleted):
    """Every ResourceIdentifier listed for these ids, keyed by resourceId, across all pages."""
    cfg = ctx.client("config")
    out, token = {}, None
    while True:
        kwargs = {
            "resourceType": resource_type,
            "resourceIds": list(resource_ids),
            "includeDeletedResources": include_deleted,
        }
        if token:
            kwargs["nextToken"] = token
        resp = cfg.list_discovered_resources(**kwargs)
        for ident in resp["resourceIdentifiers"]:
            out[ident.get("resourceId")] = ident
        token = resp.get("nextToken")
        if not token:
            return out


CHECK = "list-discovered-resources-omits-a-deleted-resource-until-include-deleted-requested"
GROUP = "resource-config"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """After one of two recorded buckets is deleted, ListDiscoveredResources omits it unless
    includeDeletedResources=True, which adds it with a resourceDeletionTime after its discovery;
    the surviving bucket is listed in both arms without a deletion time."""
    _restore_config_recorder_on_teardown(ctx)
    s3 = ctx.client("s3")
    scenario = "config-include-deleted-resources"

    _start_recording(ctx, scenario)

    doomed = _create_bucket(ctx, "sim2real-behav-cfg-doomed-", scenario)
    control = _create_bucket(ctx, "sim2real-behav-cfg-control-", scenario)

    # Both buckets must be RECORDED before a later absence can be attributed to the flag.
    _await_history_items(
        ctx, "AWS::S3::Bucket", doomed, timeout_s=_CI_BUDGET_S,
        description=f"the discovery configuration item for the bucket to be deleted ({doomed!r})",
    )
    doomed_history = _history_items(ctx, "AWS::S3::Bucket", doomed)
    discovered_at = doomed_history[-1]["configurationItemCaptureTime"]
    _await_history_items(
        ctx, "AWS::S3::Bucket", control, timeout_s=_CI_BUDGET_S,
        description=f"the discovery configuration item for the surviving bucket ({control!r})",
    )

    both = [doomed, control]
    before = _discovered(ctx, "AWS::S3::Bucket", both, include_deleted=False)
    assert set(before) == set(both), (
        f"both recorded buckets must be discoverable before either is deleted: expected "
        f"{sorted(both)!r}, got {sorted(before)!r}"
    )
    deletion_times = {k: v.get("resourceDeletionTime") for k, v in before.items()}
    assert all(t is None for t in deletion_times.values()), (
        f"a live resource must carry no resourceDeletionTime: got {deletion_times!r}"
    )
    assert before[doomed].get("resourceName") == doomed, (
        f"Config must key an S3 bucket by its name: resourceId {doomed!r} came back with "
        f"resourceName {before[doomed].get('resourceName')!r}"
    )

    # --- delete exactly one of the two, out of band, and make the deletion observably complete ---
    # Service timestamps can be second-granular: cross a tick so deletion follows discovery.
    time.sleep(1.1)
    _empty_and_delete_bucket(ctx, doomed)
    gone, gone_message = _poll_until(
        lambda: _error_code_or_success(lambda: s3.head_bucket(Bucket=doomed)),
        lambda c: c[0] in ("404", "NoSuchBucket"),
        timeout_s=_BUCKET_GONE_BUDGET_S,
        interval_s=1,
        description=f"bucket {doomed!r} stops resolving through HeadBucket",
        ctx=ctx,
    )
    assert gone in ("404", "NoSuchBucket"), (
        f"expected HeadBucket on the deleted bucket to answer 404/NoSuchBucket, got {gone!r}"
    )
    assert gone_message == "Not Found", (
        f"expected HeadBucket on the deleted bucket to carry message 'Not Found', got {gone_message!r}"
    )

    deleted_items = _await_history_items(
        ctx,
        "AWS::S3::Bucket",
        doomed,
        predicate=lambda items: any(
            i.get("configurationItemStatus") == "ResourceDeleted" for i in items
        ),
        timeout_s=_DELETION_CI_BUDGET_S,
        description=f"a ResourceDeleted configuration item for bucket {doomed!r}",
    )
    deleted_item = next(
        i for i in deleted_items if i.get("configurationItemStatus") == "ResourceDeleted"
    )

    # --- the same listing twice, differing only in includeDeletedResources ---
    excluded = _discovered(ctx, "AWS::S3::Bucket", both, include_deleted=False)
    included = _discovered(ctx, "AWS::S3::Bucket", both, include_deleted=True)

    assert doomed not in excluded, (
        f"includeDeletedResources=False must OMIT the deleted bucket, but {doomed!r} was still "
        f"listed as {excluded.get(doomed)!r} (its ResourceDeleted item was captured at "
        f"{deleted_item.get('configurationItemCaptureTime')!r})"
    )
    assert control in excluded, (
        f"includeDeletedResources=False must still list the surviving bucket {control!r}; got "
        f"{sorted(excluded)!r} - without it the omission above would only mean the listing is empty"
    )
    assert doomed in included, (
        f"includeDeletedResources=True must include the deleted bucket {doomed!r}; got "
        f"{sorted(included)!r}"
    )
    assert control in included, (
        f"includeDeletedResources=True must not DROP live resources: {control!r} missing from "
        f"{sorted(included)!r}"
    )

    deletion_time = included[doomed].get("resourceDeletionTime")
    assert deletion_time is not None, (
        f"the deleted bucket's identifier must carry resourceDeletionTime when deleted resources are "
        f"requested; got {included[doomed]!r}"
    )
    assert deletion_time > discovered_at, (
        f"resourceDeletionTime {deletion_time!r} must be strictly later than the bucket's own "
        f"discovery configurationItemCaptureTime {discovered_at!r}"
    )
    assert included[control].get("resourceDeletionTime") is None, (
        f"the surviving bucket must carry no resourceDeletionTime even when deleted resources are "
        f"requested; got {included[control]!r}"
    )

    # --- the omission is stable, not a race this check happened to win ---
    repeats = []
    for _ in range(_FREEZE_READS):
        time.sleep(1)
        repeats.append(doomed in _discovered(ctx, "AWS::S3::Bucket", both, include_deleted=False))
    assert repeats == [False] * _FREEZE_READS, (
        f"the deleted bucket leaked into the includeDeletedResources=False listing on a repeat read: "
        f"expected {[False] * _FREEZE_READS!r}, got {repeats!r}"
    )


def _restore_config_recorder_on_teardown(ctx) -> None:
    """Snapshot the account's recorder and delivery channel and restore them at teardown."""
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
