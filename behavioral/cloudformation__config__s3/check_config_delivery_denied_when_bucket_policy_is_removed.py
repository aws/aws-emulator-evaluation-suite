"""config-delivery-denied-when-bucket-policy-is-removed."""

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


def _error_code(fn):
    """The AWS error code raised by fn(); raises if fn() unexpectedly succeeds, so an accepted
    request is never reported as an error-code mismatch."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError("the call was expected to be rejected but it succeeded")


_CALL_SUCCEEDED = "<call succeeded>"


def _error_code_or_success(fn):
    """For POLLING a condition expressed as an error code. A success returns _CALL_SUCCEEDED, a
    truthy value no AWS error code can equal, so it never reads as a missing or mismatched code."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return _CALL_SUCCEEDED


def _retry_throttled(fn, attempts=8, base_delay=2.0):
    # Config's control plane has a very low burst limit and trips ThrottlingException; retry
    # only that, re-raising any domain error.
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
    """Resolve the exact `sim2real-behav-config-role`, creating it if absent. A scan for any role
    trusting config.amazonaws.com could pick a deliberately broken sibling role, so the scan is
    only a last resort when iam:CreateRole is denied."""
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
            # IAM exposes no "role is assumable" condition; the retry in _create_recorder bounds
            # propagation.
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
    # IAM exposes no "role is assumable" condition; retries at first use bound propagation.
    return name, arn


def _clear_recorders(ctx):
    """There is one configuration recorder per account and Region, so a leftover recorder turns
    PutConfigurationRecorder into MaxNumberOfConfigurationRecordersExceededException."""
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
    # PutConfigurationRecorder validates that Config can assume the role, which fails until a
    # freshly created role has propagated.
    last = None
    for attempt in range(8):
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
            time.sleep(5 * (attempt + 1))
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
    """Start the recorder and wait until it reports recording=True. Not gated on lastStatus
    SUCCESS: on AWS it stays PENDING for over 300s on a fresh recorder while items are produced."""
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
        timeout_s=90,
        interval_s=2,
        description=f"recorder {name!r} reports recording=True",
    )


def _stop_recorder(ctx, name):
    cfg = ctx.client("config")
    _retry_throttled(lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name))
    _poll_until(
        lambda: _recorder_status(ctx, name),
        lambda s: s is not None and s.get("recording") is False,
        timeout_s=90,
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


def _start_recording(ctx, scenario, recording_group=None):
    """A delivery bucket with the Config delivery policy, a delivery channel, and a running
    recorder. Returns (recorder_name, channel_name, bucket)."""
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
    """Poll for configuration items; on timeout report the recorder status too, so a stalled
    recorder is distinguishable from an unrecorded resource."""
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
    """Every configuration item Config holds for a resource, paginated. An
    ResourceNotDiscoveredException means Config has recorded nothing for it, which is an
    empty history rather than an error for polling purposes."""
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
        interval_s=5,
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
    propagating. For POLLING only - the negative leg asserts through _error_code instead."""
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


def _bucket_keys(ctx, bucket):
    s3 = ctx.client("s3")
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


CHECK = "config-delivery-denied-when-bucket-policy-is-removed"
GROUP = 'delivery-channel'
SERVICES = ['cloudformation', 'config', 's3']


@tags("axis:negative-delivery", "cap:c7", "concern:data-plane", "concern:e2e",
      "concern:negative-classes", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """With the delivery bucket's policy deleted, DeliverConfigSnapshot still returns an id but
    delivery settles on FAILURE with a lastErrorCode and no object; restoring only that policy
    makes the identical delivery reach SUCCESS and write an object naming its snapshot id.
    """
    _restore_config_recorder_on_teardown(ctx)
    cfg = ctx.client("config")
    s3 = ctx.client("s3")
    scenario = "config-delivery-denied"

    _clear_recorders(ctx)
    _clear_delivery_channels(ctx)

    # A fully working delivery path first: the channel could not even be created without the policy
    # (PutDeliveryChannel rejects an unpermissioned bucket with InsufficientDeliveryPolicyException),
    # so the policy is provably in place before anything is broken.
    bucket = _create_delivery_bucket(ctx, scenario)
    recorder = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, recorder)
    channel = ctx.unique_name("sim2real-behav-cfg-channel-")
    _create_delivery_channel(ctx, channel, bucket)
    _start_recorder(ctx, recorder)

    # On AWS, revoking the recorder role's s3:PutObject does not break delivery,
    # because the bucket policy grants config.amazonaws.com directly and same-account S3 access is
    # allowed by either side. The bucket policy is therefore the only single grant whose removal
    # actually denies the write.
    s3.delete_bucket_policy(Bucket=bucket)
    _poll_until(
        lambda: _error_code_or_success(lambda: s3.get_bucket_policy(Bucket=bucket)),
        lambda c: c == "NoSuchBucketPolicy",
        timeout_s=120,
        interval_s=3,
        description=f"the delivery bucket {bucket!r} reports no bucket policy",
    )

    bad_snapshot = _retry_throttled(
        lambda: cfg.deliver_config_snapshot(deliveryChannelName=channel)
    )
    bad_id = bad_snapshot["configSnapshotId"]
    assert bad_id, (
        f"DeliverConfigSnapshot must still be accepted even when delivery will fail: "
        f"{bad_snapshot!r}"
    )
    bad_info = _poll_until(
        lambda: cfg.describe_delivery_channel_status(DeliveryChannelNames=[channel])[
            "DeliveryChannelsStatus"
        ][0].get("configSnapshotDeliveryInfo", {}),
        lambda i: i.get("lastStatus") in ("SUCCESS", "FAILURE"),
        timeout_s=420,
        interval_s=10,
        description="snapshot delivery without a bucket policy reaches a terminal lastStatus",
    )
    bad_attempted_at = bad_info["lastAttemptTime"]
    assert bad_info.get("lastStatus") == "FAILURE", (
        f"deleting the delivery bucket's policy must make snapshot delivery FAIL, got "
        f"{bad_info!r}"
    )
    assert bad_info.get("lastErrorCode"), (
        f"a failed delivery must report a lastErrorCode: {bad_info!r}"
    )
    bad_keys = _bucket_keys(ctx, bucket)
    assert [k for k in bad_keys if bad_id in k] == [], (
        f"the snapshot was delivered into {bucket!r} despite the bucket policy being removed; "
        f"bucket held {bad_keys!r}"
    )

    s3.put_bucket_policy(
        Bucket=bucket, Policy=_S3_DELIVERY_BUCKET_POLICY.format(bucket=bucket)
    )
    _poll_until(
        lambda: _error_code_or_success(lambda: s3.get_bucket_policy(Bucket=bucket)),
        lambda c: c == _CALL_SUCCEEDED,
        timeout_s=120,
        interval_s=3,
        description=f"the delivery bucket {bucket!r} reports a bucket policy again",
    )

    # DeliverConfigSnapshot is hard rate-limited, so the control delivery is issued once and only
    # its status is polled.
    good_id = _retry_throttled(
        lambda: cfg.deliver_config_snapshot(deliveryChannelName=channel)
    )["configSnapshotId"]
    assert good_id != bad_id, (bad_id, good_id)
    good_info = _poll_until(
        lambda: cfg.describe_delivery_channel_status(DeliveryChannelNames=[channel])[
            "DeliveryChannelsStatus"
        ][0].get("configSnapshotDeliveryInfo", {}),
        lambda i: i.get("lastStatus") == "SUCCESS"
        and i.get("lastSuccessfulTime") is not None
        and i.get("lastSuccessfulTime") > bad_attempted_at,
        timeout_s=420,
        interval_s=10,
        description="the delivery issued after the policy was restored reaches SUCCESS",
    )
    assert good_info["lastStatus"] == "SUCCESS", (
        f"the control delivery did not succeed, so the negative leg proves nothing: {good_info!r}"
    )
    good_keys = _poll_until(
        lambda: _bucket_keys(ctx, bucket),
        lambda ks: any(good_id in k for k in ks),
        timeout_s=420,
        interval_s=15,
        description=f"the control delivery writes an object naming {good_id!r}",
    )
    control_key = next(k for k in good_keys if good_id in k)
    body = s3.get_object(Bucket=bucket, Key=control_key)["Body"].read()
    assert body, f"the control object at {control_key!r} is empty"
    # The denied snapshot must STILL be absent: the control proves the bucket was writable all along,
    # so the only thing that suppressed the first delivery was the policy that was removed.
    assert [k for k in good_keys if bad_id in k] == [], (
        f"the snapshot delivered without a bucket policy appeared after all: "
        f"{[k for k in good_keys if bad_id in k]!r}"
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
