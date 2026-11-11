"""config-compliance-change-event-reaches-eventbridge-with-old-and-new-verdicts."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_FIRST_EVENT_BUDGET_S = 540.0
_SECOND_EVENT_BUDGET_S = 420.0
_VERSIONING_BUDGET_S = 120.0
_RECORDED_BUDGET_S = 300.0
_RULE_DELETE_BUDGET_S = 300.0

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

# Three transitions plus IAM propagation plus Config's low control-plane burst limit need
# more than 300 s.
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
    """The error code raised by fn(), or None on success. For polling only, never asserted."""
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
    """A bounded retry with a stated reason that raises on timeout."""
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
    """True only if the trust policy names exactly config.amazonaws.com (a substring test
    would also match a service-linked role Config cannot assume for recording/delivery)."""
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
    """Resolve one fixed-name recorder role, creating it if absent.
    Not a scan for any role trusting config.amazonaws.com, which could adopt another check's
    deliberately broken role; that scan is only a fallback when iam:CreateRole is denied."""
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
    """Config allows one recorder per account and Region, so a leftover one makes
    PutConfigurationRecorder fail MaxNumberOfConfigurationRecordersExceededException."""
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
    """The delivery channel is the recorder's twin singleton (one per account and Region)."""
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
    # freshly created role has propagated, and IAM exposes no signal that a role has become
    # assumable, so this bounded retry is what makes the check correct.
    deadline = time.monotonic() + _budget_s(ctx, 180.0)
    last = None
    while True:
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
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"recorder {name!r} accepted: the run budget ended first; not graded") from None
                raise last
            time.sleep(2)


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

    Not gated on lastStatus == 'SUCCESS': it can stay PENDING for over 300 s on a fresh
    recorder while configuration items are already being produced."""
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
        timeout_s=_budget_s(ctx, _TRANSITION_BUDGET_S),
        interval_s=2,
        description=f"recorder {name!r} reports recording=True",
        ctx=ctx,
    )


def _stop_recorder(ctx, name):
    cfg = ctx.client("config")
    _retry_throttled(lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name))
    _poll_until(
        lambda: _recorder_status(ctx, name),
        lambda s: s is not None and s.get("recording") is False,
        timeout_s=_budget_s(ctx, _TRANSITION_BUDGET_S),
        interval_s=2,
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
    deadline = time.monotonic() + _budget_s(ctx, 120.0)
    last = None
    while True:
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
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"delivery channel {name!r} accepted: the run budget ended first; not graded") from None
                raise last
            time.sleep(2)


def _start_recording(ctx, scenario, recording_group=None, sns_topic_arn=None):
    """Create a delivery bucket with the Config delivery policy, a delivery channel and a
    running recorder. Returns (recorder, channel, bucket)."""
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
    """Every configuration item Config holds for a resource, paginated.
    ResourceNotDiscoveredException is treated as an empty history."""
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
    """Poll for configuration items; on timeout, report the recorder's own status so a stalled
    recorder is distinguishable from an unrecorded resource."""
    predicate = predicate or (lambda items: bool(items))
    description = description or f"a configuration item for {resource_type} {resource_id!r}"
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _history_items(ctx, resource_type, resource_id)
        if predicate(last):
            return last
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}. Recorder status: "
        f"{_all_recorder_statuses(ctx)!r}"
    )


def _config_rule_names(ctx):
    cfg = ctx.client("config")
    names = []
    for page in cfg.get_paginator("describe_config_rules").paginate():
        names.extend(r["ConfigRuleName"] for r in page.get("ConfigRules", []))
    return names


def _delete_config_rule(ctx, rule_name):
    """delete_config_rule is asynchronous: the rule sits in DELETING and blocks a re-put of the same
    name, so poll it out of describe_config_rules rather than assuming the call finished."""
    cfg = ctx.client("config")
    try:
        _retry_throttled(lambda: cfg.delete_config_rule(ConfigRuleName=rule_name))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchConfigRuleException":
            return
        raise
    _poll_until(
        lambda: _config_rule_names(ctx),
        lambda names: rule_name not in names,
        timeout_s=_RULE_DELETE_BUDGET_S,
        interval_s=2,
        description=f"config rule {rule_name!r} leaves describe_config_rules",
    )


def _put_managed_rule(ctx, source_identifier, scope, scenario, name=None):
    cfg = ctx.client("config")
    rule = name or ctx.unique_name("sim2real-behav-cfg-rule-")
    _retry_throttled(
        lambda: cfg.put_config_rule(
            ConfigRule={
                "ConfigRuleName": rule,
                "Source": {"Owner": "AWS", "SourceIdentifier": source_identifier},
                "Scope": scope,
            },
            Tags=[{"Key": "sim2real", "Value": scenario}],
        )
    )
    ctx.on_cleanup(lambda: _delete_config_rule(ctx, rule))
    return rule


def _evaluation_results(ctx, rule_name):
    cfg = ctx.client("config")
    out = []
    for page in cfg.get_paginator("get_compliance_details_by_config_rule").paginate(
        ConfigRuleName=rule_name
    ):
        out.extend(page.get("EvaluationResults", []))
    return out


def _result_for(results, resource_id):
    for r in results:
        qual = r.get("EvaluationResultIdentifier", {}).get("EvaluationResultQualifier", {})
        if qual.get("ResourceId") == resource_id:
            return r
    return None


def _create_queue(ctx, scenario):
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-cfg-q-").replace("_", "-")
    url = sqs.create_queue(QueueName=name, tags={"sim2real": scenario})["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _create_event_rule_to_queue(ctx, scenario, pattern):
    """An EventBridge rule on the DEFAULT bus delivering into a queue this check owns. The queue policy
    is written after the rule exists so it can name the rule's ARN in its condition. Returns
    (rule_name, queue_url)."""
    events = ctx.client("events")
    sqs = ctx.client("sqs")
    queue_url, queue_arn = _create_queue(ctx, scenario)
    rule_name = ctx.unique_name("sim2real-behav-cfg-eb-").replace("_", "-")
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Description="sim2real behavioral fidelity probe: AWS Config compliance change events",
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )["RuleArn"]
    target_id = "sim2real-target-1"
    sqs.set_queue_attributes(
        QueueUrl=queue_url,
        Attributes={
            "Policy": json.dumps(
                {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Sid": "AllowEventBridgeDelivery",
                            "Effect": "Allow",
                            "Principal": {"Service": "events.amazonaws.com"},
                            "Action": "sqs:SendMessage",
                            "Resource": queue_arn,
                            "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
                        }
                    ],
                }
            )
        },
    )
    events.put_targets(Rule=rule_name, Targets=[{"Id": target_id, "Arn": queue_arn}])

    def _teardown():
        try:
            events.remove_targets(Rule=rule_name, Ids=[target_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            events.delete_rule(Name=rule_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_teardown)
    return rule_name, queue_url


def _drain_events(ctx, queue_url, *, timeout_s, predicate, description, seen=None):
    """Long-poll the target queue, accumulating parsed EventBridge events, until predicate(seen) holds.
    The long polls of up to 20 s ARE the wait; the loop is bounded and RAISES on timeout."""
    sqs = ctx.client("sqs")
    seen = seen if seen is not None else []
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        wait_s = max(1, min(20, int(deadline - time.monotonic())))
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=wait_s, VisibilityTimeout=60
        )
        for raw in resp.get("Messages", []):
            seen.append(json.loads(raw["Body"]))
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=raw["ReceiptHandle"])
        if predicate(seen):
            return seen
    if _budget_spent(ctx):
        raise TimeoutError(f"{description}: the run budget ended first; not graded")
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Saw {len(seen)} event(s): "
        f"{[(e.get('detail-type'), (e.get('detail') or {}).get('messageType')) for e in seen]!r}"
    )


def _qualifier(detail, side):
    return (
        (detail.get(side) or {})
        .get("evaluationResultIdentifier", {})
        .get("evaluationResultQualifier", {})
    )


def _events_for(seen, rule_name, compliance):
    """Events about one rule reporting one verdict. The resource identity is asserted by the
    caller rather than filtered here, so a missing field fails instead of being skipped."""
    out = []
    for event in seen:
        detail = event.get("detail") or {}
        if _qualifier(detail, "newEvaluationResult").get("configRuleName") != rule_name:
            continue
        if (detail.get("newEvaluationResult") or {}).get("complianceType") != compliance:
            continue
        out.append(event)
    return out


CHECK = "config-compliance-change-event-reaches-eventbridge-with-old-and-new-verdicts"
GROUP = "e2e"
SERVICES = ["config", "events", "sqs"]


@tags("axis:happy-path", "cap:c3", "concern:e2e", "concern:eventing", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A Config rule verdict change reaches EventBridge carrying both verdicts: NON_COMPLIANT first,
    then COMPLIANT with oldEvaluationResult NON_COMPLIANT after versioning is enabled, read at an
    SQS target and cross-checked against Config's compliance detail.
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    s3 = ctx.client("s3")
    account = ctx.client("sts").get_caller_identity()["Account"]
    scenario = "config-compliance-change-eventbridge"

    _eb_rule, queue_url = _create_event_rule_to_queue(
        ctx,
        scenario,
        # Filter on source and detail-type only; per-rule filtering happens in Python.
        {"source": ["aws.config"], "detail-type": ["Config Rules Compliance Change"]},
    )

    _start_recording(ctx, scenario)

    bucket = _create_bucket(ctx, "sim2real-behav-cfg-evt-", scenario)
    off = s3.get_bucket_versioning(Bucket=bucket)
    assert off.get("Status") is None, (
        f"the bucket under test must start with versioning off, got {off!r}"
    )

    rule = _put_managed_rule(
        ctx,
        "S3_BUCKET_VERSIONING_ENABLED",
        {"ComplianceResourceTypes": ["AWS::S3::Bucket"], "ComplianceResourceId": bucket},
        scenario,
    )

    seen = _drain_events(
        ctx,
        queue_url,
        timeout_s=_FIRST_EVENT_BUDGET_S,
        predicate=lambda s: bool(_events_for(s, rule, "NON_COMPLIANT")),
        description=(
            f"a Config Rules Compliance Change event for rule {rule!r} reporting NON_COMPLIANT for "
            f"bucket {bucket!r}"
        ),
    )
    first = _events_for(seen, rule, "NON_COMPLIANT")[0]
    detail = first["detail"]
    assert first.get("source") == "aws.config", (
        f"the event's source must be aws.config, got {first.get('source')!r}"
    )
    assert first.get("detail-type") == "Config Rules Compliance Change", (
        f"expected detail-type 'Config Rules Compliance Change', got {first.get('detail-type')!r}"
    )
    assert first.get("account") == account, (
        f"the event was attributed to account {first.get('account')!r}, expected {account!r}"
    )
    assert first.get("region") == ctx.region, (
        f"the event was attributed to region {first.get('region')!r}, expected {ctx.region!r}"
    )
    assert detail.get("messageType") == "ComplianceChangeNotification", (
        f"expected detail.messageType ComplianceChangeNotification, got "
        f"{detail.get('messageType')!r}"
    )
    assert detail.get("resourceType") == "AWS::S3::Bucket", (
        f"expected detail.resourceType AWS::S3::Bucket, got {detail.get('resourceType')!r}"
    )
    assert detail.get("resourceId") == bucket, (
        f"the event names resource {detail.get('resourceId')!r}, expected the bucket this check "
        f"created ({bucket!r})"
    )
    assert detail["newEvaluationResult"]["complianceType"] == "NON_COMPLIANT", (
        f"a bucket with versioning off must be reported NON_COMPLIANT, got "
        f"{detail['newEvaluationResult'].get('complianceType')!r}"
    )
    first_recorded = detail["newEvaluationResult"].get("resultRecordedTime")
    assert first_recorded, (
        f"the event's newEvaluationResult must carry a resultRecordedTime, got {detail!r}"
    )

    # --- fix the resource out of band, then make Config re-evaluate ---
    # The first verdict was recorded before its event arrived; passing a second boundary first
    # keeps a second-resolution resultRecordedTime of the re-evaluation distinct from it.
    time.sleep(1.1)
    s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    live = _poll_until(
        lambda: s3.get_bucket_versioning(Bucket=bucket).get("Status"),
        lambda v: v == "Enabled",
        timeout_s=_budget_s(ctx, _VERSIONING_BUDGET_S),
        interval_s=1,
        description=f"bucket {bucket!r} reads back versioning Enabled",
        ctx=ctx,
    )
    assert live == "Enabled", f"expected versioning Enabled, got {live!r}"

    _await_history_items(
        ctx,
        "AWS::S3::Bucket",
        bucket,
        predicate=lambda items: any(
            json.loads(
                i.get("supplementaryConfiguration", {}).get("BucketVersioningConfiguration", "{}")
            ).get("status")
            == "Enabled"
            for i in items
        ),
        timeout_s=_RECORDED_BUDGET_S,
        description=f"Config records bucket {bucket!r} with versioning Enabled",
    )
    _retry_throttled(lambda: cfg.start_config_rules_evaluation(ConfigRuleNames=[rule]))

    seen = _drain_events(
        ctx,
        queue_url,
        timeout_s=_SECOND_EVENT_BUDGET_S,
        predicate=lambda s: bool(_events_for(s, rule, "COMPLIANT")),
        description=(
            f"a second Config Rules Compliance Change event for rule {rule!r} reporting COMPLIANT "
            f"for bucket {bucket!r} once versioning is enabled"
        ),
        seen=seen,
    )
    flip = _events_for(seen, rule, "COMPLIANT")[0]
    flip_detail = flip["detail"]
    assert flip_detail["newEvaluationResult"]["complianceType"] == "COMPLIANT", (
        f"expected the flipped verdict to be COMPLIANT, got "
        f"{flip_detail['newEvaluationResult'].get('complianceType')!r}"
    )
    old = flip_detail.get("oldEvaluationResult")
    assert isinstance(old, dict), (
        f"a compliance CHANGE event must carry an oldEvaluationResult object for comparison; got "
        f"{old!r}. A target that emits only the current verdict fails exactly here"
    )
    assert old.get("complianceType") == "NON_COMPLIANT", (
        f"oldEvaluationResult must still report the verdict this resource is moving AWAY from: "
        f"expected NON_COMPLIANT, got {old.get('complianceType')!r}"
    )
    assert _qualifier(flip_detail, "oldEvaluationResult").get("configRuleName") == rule, (
        f"oldEvaluationResult describes rule "
        f"{_qualifier(flip_detail, 'oldEvaluationResult').get('configRuleName')!r}, expected {rule!r}"
    )
    # resultRecordedTime's type in the event detail is undocumented, so only inequality is compared.
    assert str(flip_detail["newEvaluationResult"].get("resultRecordedTime")) != str(
        old.get("resultRecordedTime")
    ), (
        f"the two verdicts in one event carry the identical resultRecordedTime "
        f"({flip_detail['newEvaluationResult'].get('resultRecordedTime')!r}), so they are not two "
        f"distinct evaluations"
    )

    # --- cross-check the consumer's view against Config's own compliance detail ---
    at_config = _poll_until(
        lambda: _result_for(_evaluation_results(ctx, rule), bucket),
        lambda r: r is not None and r["ComplianceType"] == "COMPLIANT",
        timeout_s=_budget_s(ctx, _VERSIONING_BUDGET_S),
        interval_s=2,
        description=(
            f"GetComplianceDetailsByConfigRule agrees with the delivered event that {bucket!r} is "
            f"COMPLIANT under {rule!r}"
        ),
        ctx=ctx,
    )
    assert at_config["ComplianceType"] == "COMPLIANT", (
        f"Config's own compliance detail disagrees with the event it delivered: "
        f"{at_config['ComplianceType']!r}"
    )
    assert (
        at_config["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"] == bucket
    ), at_config


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
