"""config-remediation-execution-without-configuration-rejected-and-resource-untouched."""

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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition", ctx=None):
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
    """Resolve one fixed-name recorder role, creating it if absent.
    Not a scan for any role trusting config.amazonaws.com, which could adopt another check's
    deliberately broken role; that scan is only a fallback when iam:CreateRole is denied.
    """
    global _ROLE_ARN_CACHE
    if _ROLE_ARN_CACHE:
        return _ROLE_ARN_CACHE
    iam = ctx.client("iam")
    arn = None
    try:
        role = iam.get_role(RoleName=_CONFIG_ROLE_NAME)["Role"]
        assert _trusts_config_service(role.get("AssumeRolePolicyDocument")), (
            f"{_CONFIG_ROLE_NAME!r} exists but does not trust config.amazonaws.com: {role!r}"
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
            # IAM exposes no signal that a role has become assumable; the bounded retry inside
            # _create_recorder waits out propagation.
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


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for page in iam.get_paginator("list_attached_role_policies").paginate(RoleName=role_name):
            for pol in page.get("AttachedPolicies", []):
                try:
                    iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
        for page in iam.get_paginator("list_role_policies").paginate(RoleName=role_name):
            for pol in page.get("PolicyNames", []):
                try:
                    iam.delete_role_policy(RoleName=role_name, PolicyName=pol)
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_role(ctx, prefix, trust_service, scenario, managed_policies=(), inline=None):
    """A role this check owns and will delete, trusting exactly one AWS service principal."""
    iam = ctx.client("iam")
    name = ctx.unique_name(prefix)
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": trust_service},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Description=f"sim2real behavioral fidelity probe role ({scenario})",
        Tags=[{"Key": "sim2real", "Value": scenario}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, name))
    for policy_arn in managed_policies:
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
    if inline:
        iam.put_role_policy(
            RoleName=name,
            PolicyName="sim2real-inline",
            PolicyDocument=json.dumps(inline),
        )
    return name, arn


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
    # A versioned bucket needs every version AND every delete marker removed, else
    # delete_bucket fails BucketNotEmpty; list_objects_v2 alone never sees them.
    try:
        for page in s3.get_paginator("list_object_versions").paginate(Bucket=bucket):
            for entry in list(page.get("Versions", [])) + list(page.get("DeleteMarkers", [])):
                try:
                    s3.delete_object(
                        Bucket=bucket, Key=entry["Key"], VersionId=entry["VersionId"]
                    )
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


def _create_bucket(ctx, ctx_prefix, scenario):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name(ctx_prefix).replace("_", "-").lower()
    kwargs = {"Bucket": bucket}
    if ctx.region and ctx.region != "us-east-1":
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
    s3.put_bucket_policy(
        Bucket=bucket, Policy=_S3_DELIVERY_BUCKET_POLICY.format(bucket=bucket)
    )
    return bucket


def _create_recorder(ctx, name, recording_group=None, role_arn=None):
    cfg = ctx.client("config")
    recorder = {
        "name": name,
        "roleARN": role_arn or _ensure_config_role(ctx),
        "recordingGroup": recording_group or dict(_DEFAULT_RECORDING_GROUP),
    }
    # PutConfigurationRecorder validates that Config can assume the role, which fails until
    # a freshly created role has propagated. This bounded retry is what makes the check
    # correct.
    last = None
    deadline = time.monotonic() + _budget_s(ctx, 180)
    while time.monotonic() < deadline:
        try:
            _retry_throttled(
                lambda: cfg.put_configuration_recorder(ConfigurationRecorder=recorder)
            )
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
            time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"recorder {name!r} accepted: the run budget ended first; not graded")
    raise last


def _put_recording_group(ctx, name, recording_group, role_arn=None):
    """Re-put an EXISTING recorder with a different recordingGroup. No cleanup is registered:
    the recorder's delete is already registered by the _create_recorder that made it."""
    cfg = ctx.client("config")
    _retry_throttled(
        lambda: cfg.put_configuration_recorder(
            ConfigurationRecorder={
                "name": name,
                "roleARN": role_arn or _ensure_config_role(ctx),
                "recordingGroup": recording_group,
            }
        )
    )


def _recorder_status(ctx, name):
    cfg = ctx.client("config")
    statuses = cfg.describe_configuration_recorder_status(
        ConfigurationRecorderNames=[name]
    ).get("ConfigurationRecordersStatus", [])
    return statuses[0] if statuses else None


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
        timeout_s=_budget_s(ctx, 90),
        ctx=ctx,
        interval_s=2,
        description=f"recorder {name!r} reports recording=True",
    )


def _stop_recorder(ctx, name):
    cfg = ctx.client("config")
    _retry_throttled(lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name))
    _poll_until(
        lambda: _recorder_status(ctx, name),
        lambda s: s is not None and s.get("recording") is False,
        timeout_s=_budget_s(ctx, 90),
        ctx=ctx,
        interval_s=2,
        description=f"recorder {name!r} reports recording=False",
    )


def _create_delivery_channel(ctx, name, bucket):
    cfg = ctx.client("config")
    channel = {"name": name, "s3BucketName": bucket}
    # The freshly-written bucket policy is eventually consistent; Config rejects a
    # delivery channel whose bucket policy has not propagated with
    # InsufficientDeliveryPolicyException.
    last = None
    deadline = time.monotonic() + _budget_s(ctx, 108)
    while time.monotonic() < deadline:
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
            time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"delivery channel {name!r} accepted: the run budget ended first; not graded")
    raise last


def _start_recording(ctx, scenario, recording_group=None):
    """Create a delivery bucket with the Config delivery policy, a delivery channel and a
    running recorder. Returns (recorder, channel, bucket)."""
    _clear_recorders(ctx)
    _clear_delivery_channels(ctx)
    bucket = _create_delivery_bucket(ctx, scenario)
    recorder = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, recorder, recording_group=recording_group)
    channel = ctx.unique_name("sim2real-behav-cfg-channel-")
    _create_delivery_channel(ctx, channel, bucket)
    _start_recorder(ctx, recorder)
    return recorder, channel, bucket


def _await_history_items(ctx, resource_type, resource_id, *, timeout_s, predicate=None,
                         description=None):
    """Poll for configuration items; on timeout, report the recorder's own status so a stalled
    recorder is distinguishable from an unrecorded resource."""
    predicate = predicate or (lambda items: bool(items))
    description = description or f"a configuration item for {resource_type} {resource_id!r}"
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
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


def _all_recorder_statuses(ctx):
    cfg = ctx.client("config")
    try:
        return [
            {k: s.get(k) for k in ("name", "recording", "lastStatus", "lastErrorCode",
                                   "lastErrorMessage")}
            for s in cfg.describe_configuration_recorder_status()[
                "ConfigurationRecordersStatus"]
        ]
    except ClientError as exc:
        return f"unreadable: {exc}"


def _history_items(ctx, resource_type, resource_id):
    """Every configuration item Config holds for a resource, paginated.
    ResourceNotDiscoveredException is treated as an empty history."""
    cfg = ctx.client("config")
    items = []
    try:
        for page in cfg.get_paginator("get_resource_config_history").paginate(
            resourceType=resource_type, resourceId=resource_id
        ):
            items.extend(page.get("configurationItems", []))
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotDiscoveredException":
            return []
        raise
    return items


def _create_queue(ctx, scenario, attributes=None):
    sqs = ctx.client("sqs")
    name = ctx.unique_name("sim2real-behav-cfg-q-").replace("_", "-")
    kwargs = {"QueueName": name, "tags": {"sim2real": scenario}}
    if attributes:
        kwargs["Attributes"] = attributes
    url = sqs.create_queue(**kwargs)["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    return name, url


def _delete_config_rule(ctx, rule_name):
    """delete_config_rule is asynchronous: the rule sits in DELETING and blocks a re-put of the
    same name, so poll it out of describe_config_rules rather than assuming the call finished."""
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
        timeout_s=300,
        interval_s=2,
        description=f"config rule {rule_name!r} leaves describe_config_rules",
    )


def _config_rule_names(ctx):
    cfg = ctx.client("config")
    names = []
    for page in cfg.get_paginator("describe_config_rules").paginate():
        names.extend(r["ConfigRuleName"] for r in page.get("ConfigRules", []))
    return names


def _put_managed_rule(ctx, source_identifier, scope, scenario):
    cfg = ctx.client("config")
    rule = ctx.unique_name("sim2real-behav-cfg-rule-")
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


def _start_remediation_or_none(ctx, rule_name, resource_keys):
    """StartRemediationExecution, or None while the just-re-put configuration is still
    propagating. For POLLING only - the negative leg asserts through _error instead."""
    cfg = ctx.client("config")
    try:
        return cfg.start_remediation_execution(
            ConfigRuleName=rule_name, ResourceKeys=resource_keys
        )
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NoSuchRemediationConfigurationException":
            return None
        raise


def _evaluation_results(ctx, rule_name):
    cfg = ctx.client("config")
    out = []
    for page in cfg.get_paginator("get_compliance_details_by_config_rule").paginate(
        ConfigRuleName=rule_name
    ):
        out.extend(page.get("EvaluationResults", []))
    return out


def _compliance_details_by_resource(ctx, resource_type, resource_id):
    cfg = ctx.client("config")
    out, token = [], None
    while True:
        kwargs = {"ResourceType": resource_type, "ResourceId": resource_id}
        if token:
            kwargs["NextToken"] = token
        resp = cfg.get_compliance_details_by_resource(**kwargs)
        out.extend(resp.get("EvaluationResults", []))
        token = resp.get("NextToken")
        if not token:
            return out


def _result_for(results, resource_id):
    for r in results:
        qual = r.get("EvaluationResultIdentifier", {}).get("EvaluationResultQualifier", {})
        if qual.get("ResourceId") == resource_id:
            return r
    return None


def _deliver_until_success(ctx, channel):
    """Issue a snapshot delivery and return its id once the channel reports SUCCESS for it, else
    None. For POLLING: a delivery issued while a just-restored bucket policy is still propagating
    fails, so the retry re-issues rather than waiting on a status that will never change."""
    cfg = ctx.client("config")
    snapshot_id = cfg.deliver_config_snapshot(deliveryChannelName=channel)["configSnapshotId"]
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        info = cfg.describe_delivery_channel_status(DeliveryChannelNames=[channel])[
            "DeliveryChannelsStatus"
        ][0].get("configSnapshotDeliveryInfo", {})
        if info.get("lastStatus") == "SUCCESS":
            return snapshot_id
        if info.get("lastStatus") == "FAILURE":
            return None
        time.sleep(2)
    return None


def _bucket_keys(ctx, bucket):
    s3 = ctx.client("s3")
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


CHECK = "config-remediation-execution-without-configuration-rejected-and-resource-untouched"
GROUP = 'remediation'
SERVICES = ['config', 's3', 'ssm']


@tags("axis:rejection", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """Deleting a remediation configuration disarms remediation: StartRemediationExecution raises
    NoSuchRemediationConfigurationException and bucket versioning stays off; re-putting it makes
    the same call reach SUCCEEDED and turn versioning on.
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    s3 = ctx.client("s3")
    ssm = ctx.client("ssm")
    scenario = "config-remediation-disarmed"

    document = "AWS-ConfigureS3BucketVersioning"
    described = ssm.describe_document(Name=document)["Document"]
    param_names = {p["Name"] for p in described.get("Parameters", [])}
    assert {"BucketName", "VersioningState", "AutomationAssumeRole"} <= param_names, (
        f"{document!r} does not expose the parameters this check drives: {sorted(param_names)!r}"
    )

    _start_recording(ctx, scenario)

    bucket = _create_bucket(ctx, "sim2real-behav-cfg-remed-", scenario)
    assert s3.get_bucket_versioning(Bucket=bucket).get("Status") is None, (
        "the bucket under test must start with versioning off"
    )
    _await_history_items(
        ctx,
        "AWS::S3::Bucket",
        bucket,
        timeout_s=500,
        description=f"a configuration item for bucket {bucket!r}",
    )

    _role_name, role_arn = _create_role(
        ctx,
        "sim2real-behav-cfg-remed-role-",
        "ssm.amazonaws.com",
        scenario,
        inline={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:PutBucketVersioning", "s3:GetBucketVersioning"],
                    "Resource": f"arn:aws:s3:::{bucket}",
                }
            ],
        },
    )

    rule = _put_managed_rule(
        ctx,
        "S3_BUCKET_VERSIONING_ENABLED",
        {"ComplianceResourceTypes": ["AWS::S3::Bucket"]},
        scenario,
    )
    verdict = _poll_until(
        lambda: _result_for(_evaluation_results(ctx, rule), bucket),
        lambda r: r is not None,
        timeout_s=_budget_s(ctx, 400),
        ctx=ctx,
        interval_s=2,
        description=f"an evaluation result for bucket {bucket!r} under rule {rule!r}",
    )
    assert verdict["ComplianceType"] == "NON_COMPLIANT", (
        f"the bucket must be NON_COMPLIANT for remediation to have anything to do, got "
        f"{verdict['ComplianceType']!r}"
    )

    remediation = {
        "ConfigRuleName": rule,
        "TargetType": "SSM_DOCUMENT",
        "TargetId": document,
        "ResourceType": "AWS::S3::Bucket",
        "Automatic": False,
        "Parameters": {
            "AutomationAssumeRole": {"StaticValue": {"Values": [role_arn]}},
            "BucketName": {"ResourceValue": {"Value": "RESOURCE_ID"}},
            "VersioningState": {"StaticValue": {"Values": ["Enabled"]}},
        },
    }

    def _put_remediation():
        resp = _retry_throttled(
            lambda: cfg.put_remediation_configurations(
                RemediationConfigurations=[dict(remediation)]
            )
        )
        assert resp.get("FailedBatches", []) == [], (
            f"PutRemediationConfigurations rejected the configuration: {resp!r}"
        )

    def _delete_remediation_if_present():
        # The check deletes this configuration itself mid-run, so a run that stops before the
        # control re-arms it leaves nothing for teardown to remove.
        try:
            _retry_throttled(
                lambda: cfg.delete_remediation_configuration(
                    ConfigRuleName=rule, ResourceType="AWS::S3::Bucket"
                )
            )
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "NoSuchRemediationConfigurationException":
                raise

    _put_remediation()
    ctx.on_cleanup(_delete_remediation_if_present)

    # --- break exactly one thing: remove the remediation configuration ---
    cfg.delete_remediation_configuration(ConfigRuleName=rule, ResourceType="AWS::S3::Bucket")
    _poll_until(
        lambda: cfg.describe_remediation_configurations(ConfigRuleNames=[rule])[
            "RemediationConfigurations"
        ],
        lambda cs: cs == [],
        timeout_s=_budget_s(ctx, 200),
        ctx=ctx,
        interval_s=2,
        description=f"rule {rule!r} reports no remediation configuration",
    )

    resource_keys = [{"resourceType": "AWS::S3::Bucket", "resourceId": bucket}]
    code, message = _error(
        lambda: cfg.start_remediation_execution(
            ConfigRuleName=rule, ResourceKeys=resource_keys
        )
    )
    assert code == "NoSuchRemediationConfigurationException", (
        f"expected NoSuchRemediationConfigurationException once the remediation configuration was "
        f"deleted, got {code!r}"
    )
    expected_message = (
        f"There is no applicable RemediationConfiguration setup for AWS Config rule {rule}"
    )
    assert message == expected_message, (
        f"NoSuchRemediationConfigurationException message: {message!r} != {expected_message!r}"
    )

    versioning_during = s3.get_bucket_versioning(Bucket=bucket)
    assert versioning_during.get("Status") is None, (
        f"remediation ran despite having no configuration - the bucket was modified: "
        f"{versioning_during!r}"
    )

    # --- control: re-arm the identical configuration and issue the identical call ---
    _put_remediation()
    _poll_until(
        lambda: cfg.describe_remediation_configurations(ConfigRuleNames=[rule])[
            "RemediationConfigurations"
        ],
        lambda cs: len(cs) == 1,
        timeout_s=_budget_s(ctx, 200),
        ctx=ctx,
        interval_s=2,
        description=f"rule {rule!r} reports its remediation configuration again",
    )
    control_start = _poll_until(
        lambda: _start_remediation_or_none(ctx, rule, resource_keys),
        lambda r: r is not None,
        timeout_s=_budget_s(ctx, 200),
        ctx=ctx,
        interval_s=2,
        description="StartRemediationExecution is accepted once the configuration is back",
    )
    assert control_start["FailedItems"] == [], (
        f"the control remediation was not accepted: {control_start!r}"
    )

    control_status = _poll_until(
        lambda: cfg.describe_remediation_execution_status(
            ConfigRuleName=rule, ResourceKeys=resource_keys
        )["RemediationExecutionStatuses"],
        lambda ss: bool(ss)
        and ss[0].get("State") in ("SUCCEEDED", "FAILED"),
        timeout_s=_budget_s(ctx, 400),
        ctx=ctx,
        interval_s=2,
        description="the control remediation execution reaches a terminal state",
    )
    assert control_status[0]["State"] == "SUCCEEDED", (
        f"the control remediation did not succeed: {control_status!r}"
    )

    versioning_after = _poll_until(
        lambda: s3.get_bucket_versioning(Bucket=bucket),
        lambda v: v.get("Status") == "Enabled",
        timeout_s=_budget_s(ctx, 200),
        ctx=ctx,
        interval_s=2,
        description=f"bucket {bucket!r} reads back versioning Enabled after remediation",
    )
    assert versioning_after["Status"] == "Enabled", (
        f"the control remediation reported SUCCEEDED but the bucket was not changed: "
        f"{versioning_after!r}"
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
