"""config-rule-scoped-by-tag-evaluates-only-the-tagged-resource."""

# Mutates the account-wide singleton pair: one configuration recorder and one delivery channel
# per account per Region.
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

_CI_BUDGET_S = 480.0
_CONTROL_CI_BUDGET_S = 120.0
_EVAL_BUDGET_S = 300.0
_REPAIR_BUDGET_S = 480.0
_RULE_DELETE_BUDGET_S = 300.0

# ===== helpers =====

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

# Three recorder transitions plus IAM propagation and Config's low control-plane burst limit can
# take several minutes.
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
    """The AWS error code raised by fn(). RAISES if fn() unexpectedly SUCCEEDS: accepting input
    AWS rejects is a failure in its own right, not an error-code mismatch."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError("the call was expected to be rejected but it succeeded")


def _error_code_or_none(fn):
    """For POLLING a condition expressed as an error code. Never used inside an assert: the
    None-on-success return is exactly the falsy sentinel _error_code refuses to produce."""
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


def _poll_until(probe, predicate, *, timeout_s, interval_s=1.0, description="condition"):
    """A bounded retry with a stated reason that RAISES on timeout - never returns its last value."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
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
    """Resolve ONE deterministic recorder role: the exact `sim2real-behav-config-role`, created if
    absent. Deliberately NOT a `list_roles` scan for "any role trusting config.amazonaws.com": in a
    shared account that scan can adopt another workload's restricted role and produce a recorder
    that reports recording=True and records nothing. The broad scan only exists to cope
    with an account lacking iam:CreateRole, so it stays behind that exact error."""
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
    """There is exactly ONE customer-managed configuration recorder per account per region, so a
    leftover recorder from a previous run turns PutConfigurationRecorder into
    MaxNumberOfConfigurationRecordersExceededException. Clearing is a PRECONDITION, not cleanup, and
    it is scoped to the one singleton this check must own - not a prefix sweep."""
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
    # PutConfigurationRecorder validates that Config can assume the role, which fails until a
    # freshly created role has propagated: retry those refusals to a deadline.
    deadline = time.monotonic() + 195
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
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
            if code not in (
                "InvalidRoleException", "InsufficientPermissionsException", "AccessDeniedException"
            ) or time.monotonic() > deadline:
                raise
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

    Deliberately NOT gated on `lastStatus == 'SUCCESS'`: on a fresh recorder lastStatus can sit at
    PENDING for well over 300s while configuration items are already being produced, so waiting for
    SUCCESS is a false failure."""
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
        interval_s=2,
        description=f"recorder {name!r} reports recording=True",
    )


def _stop_recorder(ctx, name):
    cfg = ctx.client("config")
    _retry_throttled(lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name))
    _poll_until(
        lambda: _recorder_status(ctx, name),
        lambda s: s is not None and s.get("recording") is False,
        timeout_s=_TRANSITION_BUDGET_S,
        interval_s=2,
        description=f"recorder {name!r} reports recording=False",
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
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = _history_items(ctx, resource_type, resource_id)
        if predicate(last):
            return last
        time.sleep(2)
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
        interval_s=5,
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


def _tag_bucket(ctx, bucket, scenario, extra_key=None, extra_value=None):
    """Replace the bucket's tag set. S3 tagging is whole-set, so the sim2real tag is always
    re-sent alongside whatever this check is adding."""
    tag_set = [{"Key": "sim2real", "Value": scenario}]
    if extra_key:
        tag_set.append({"Key": extra_key, "Value": extra_value})
    ctx.client("s3").put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": tag_set})


def _recorded_tags(items, key):
    """The values a recorded configuration item carries for one tag key, newest item first."""
    return [i.get("tags", {}).get(key) for i in items]


def _evaluated_resource_ids(ctx, rule_name):
    return {
        r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"]
        for r in _evaluation_results(ctx, rule_name)
    }


CHECK = "config-rule-scoped-by-tag-evaluates-only-the-tagged-resource"
GROUP = "config-rule"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A rule scoped by Scope.TagKey/TagValue evaluates only the bucket carrying that tag, even after
    its own NON_COMPLIANT verdict lands; tagging the second bucket then brings it under the same
    rule, so its earlier absence was the scope predicate and not an unevaluable resource."""
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    scenario = "config-rule-tag-scope"

    _start_recording(ctx, scenario)

    # The control bucket is created FIRST so that by the time the tagged bucket's tag has been
    # recorded, the control has had strictly longer to be recorded too.
    untagged = _create_bucket(ctx, "sim2real-behav-cfg-untagged-", scenario)
    tagged = _create_bucket(ctx, "sim2real-behav-cfg-tagged-", scenario)

    # A tag key unique to this run: the account may hold other buckets, and a shared key
    # would let another resource satisfy the scope and hide a scoping bug.
    scope_key = ctx.unique_name("sim2real-scope-")
    scope_value = "in-scope"
    _tag_bucket(ctx, tagged, scenario, scope_key, scope_value)

    # Barrier 1: Config must have RECORDED the tag, not merely S3 have accepted it - the rule
    # evaluates Config's recording, so this is the real precondition.
    tagged_items = _await_history_items(
        ctx,
        "AWS::S3::Bucket",
        tagged,
        predicate=lambda items: any(i.get("tags", {}).get(scope_key) == scope_value for i in items),
        timeout_s=_CI_BUDGET_S,
        description=(
            f"a configuration item for bucket {tagged!r} carrying tag {scope_key}={scope_value}"
        ),
    )
    assert scope_value in _recorded_tags(tagged_items, scope_key), (
        f"the recorded configuration items for {tagged!r} do not carry {scope_key}={scope_value}: "
        f"{_recorded_tags(tagged_items, scope_key)!r}"
    )

    untagged_items = _await_history_items(
        ctx, "AWS::S3::Bucket", untagged, timeout_s=_CONTROL_CI_BUDGET_S,
        description=(
            f"a configuration item for the untagged control bucket {untagged!r} - without it, its "
            f"absence from the rule's results would only mean it was never recorded"
        ),
    )
    assert all(i.get("tags", {}).get(scope_key) is None for i in untagged_items), (
        f"the control bucket {untagged!r} must NOT carry the scope tag; recorded values "
        f"{_recorded_tags(untagged_items, scope_key)!r}"
    )

    rule = _put_managed_rule(
        ctx,
        "S3_BUCKET_VERSIONING_ENABLED",
        {"TagKey": scope_key, "TagValue": scope_value},
        scenario,
    )
    stored = next(
        r for r in cfg.describe_config_rules(ConfigRuleNames=[rule])["ConfigRules"]
        if r["ConfigRuleName"] == rule
    )
    assert stored["Scope"].get("TagKey") == scope_key, (
        f"the rule did not store the tag scope it was created with: expected TagKey {scope_key!r}, "
        f"got {stored['Scope']!r}"
    )
    assert stored["Scope"].get("TagValue") == scope_value, (
        f"expected TagValue {scope_value!r}, got {stored['Scope']!r}"
    )
    assert "ComplianceResourceTypes" not in stored["Scope"], (
        f"a tag-only scope must not acquire a resource-type scope on the way in: {stored['Scope']!r}"
    )

    # Barrier 2: the tagged bucket must really be evaluated, or the absence below proves nothing.
    verdict = _poll_until(
        lambda: _result_for(_evaluation_results(ctx, rule), tagged),
        lambda r: r is not None,
        timeout_s=_EVAL_BUDGET_S,
        interval_s=10,
        description=f"an evaluation result for the tagged bucket {tagged!r} under rule {rule!r}",
    )
    assert verdict["ComplianceType"] == "NON_COMPLIANT", (
        f"a bucket with versioning off must be NON_COMPLIANT under "
        f"S3_BUCKET_VERSIONING_ENABLED, got {verdict['ComplianceType']!r} for {tagged!r}"
    )

    # The absence, read only AFTER the barrier landed.
    seen = _evaluated_resource_ids(ctx, rule)
    assert seen == {tagged}, (
        f"a rule scoped to tag {scope_key}={scope_value} evaluated resources that do not carry it: "
        f"expected exactly {{{tagged!r}}}, got {sorted(seen)!r}"
    )
    assert untagged not in seen, (
        f"the untagged control bucket {untagged!r} was evaluated by a tag-scoped rule: "
        f"{sorted(seen)!r}"
    )

    # --- repair the ONE thing that made the control out of scope ---
    _tag_bucket(ctx, untagged, scenario, scope_key, scope_value)
    repaired = _poll_until(
        lambda: _result_for(_evaluation_results(ctx, rule), untagged),
        lambda r: r is not None,
        timeout_s=_REPAIR_BUDGET_S,
        interval_s=10,
        description=(
            f"the formerly-untagged bucket {untagged!r} is evaluated by rule {rule!r} once it "
            f"carries {scope_key}={scope_value} - this check never calls StartConfigRulesEvaluation, "
            f"so Config must notice the tag change by itself"
        ),
    )
    assert repaired["ComplianceType"] == "NON_COMPLIANT", (
        f"the newly in-scope bucket {untagged!r} has versioning off too, so it must also be "
        f"NON_COMPLIANT; got {repaired['ComplianceType']!r}"
    )
    assert _evaluated_resource_ids(ctx, rule) == {tagged, untagged}, (
        f"after both buckets carry the scope tag the rule must have evaluated exactly the two: got "
        f"{sorted(_evaluated_resource_ids(ctx, rule))!r}"
    )
    assert repaired["ResultRecordedTime"] > verdict["ResultRecordedTime"], (
        f"the repaired bucket's verdict was recorded at {repaired['ResultRecordedTime']!r}, which is "
        f"not after the tagged bucket's {verdict['ResultRecordedTime']!r} - so it is not a new "
        f"evaluation driven by the tag change"
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
