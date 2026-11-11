"""config-stopped-recorder-records-no-configuration-item-until-restarted."""

from __future__ import annotations

import datetime
import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

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


def _refusal(fn):
    """(Code, Message) of the AWS error raised by fn(); raises if fn() unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response.get("Error", {}) or {}
        return error.get("Code"), error.get("Message") or ""
    raise AssertionError("the call was expected to be rejected but it succeeded")


def _capped(ctx, budget_s):
    """*budget_s*, capped by the time the run has left so a wait fails with its own message."""
    left = ctx.time_left()
    return budget_s if left is None else min(budget_s, max(0.0, left - 10.0))


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


def _poll_until(
    probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _delete_role(ctx, role_name):
    iam = ctx.client("iam")
    try:
        for page in iam.get_paginator("list_attached_role_policies").paginate(
            RoleName=role_name
        ):
            for pol in page.get("AttachedPolicies", []):
                try:
                    iam.detach_role_policy(
                        RoleName=role_name, PolicyArn=pol["PolicyArn"]
                    )
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
        for page in iam.get_paginator("list_role_policies").paginate(
            RoleName=role_name
        ):
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


def _create_role(
    ctx, prefix, trust_service, scenario, managed_policies=(), inline=None
):
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
    # Propagation is retried at first use (_create_recorder).
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
                lambda n=name: cfg.stop_configuration_recorder(
                    ConfigurationRecorderName=n
                )
            )
        except ClientError:
            pass
        try:
            _retry_throttled(
                lambda n=name: cfg.delete_configuration_recorder(
                    ConfigurationRecorderName=n
                )
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
            for entry in list(page.get("Versions", [])) + list(
                page.get("DeleteMarkers", [])
            ):
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


def _create_recorder(ctx, name, role_arn, recording_group=None):
    cfg = ctx.client("config")
    recorder = {
        "name": name,
        "roleARN": role_arn,
        "recordingGroup": recording_group or dict(_DEFAULT_RECORDING_GROUP),
    }
    # PutConfigurationRecorder validates that Config can assume the role, which fails until
    # a freshly created role has propagated, so it is retried until a deadline.
    deadline = time.monotonic() + _capped(ctx, 180.0)
    while True:
        try:
            _retry_throttled(
                lambda: cfg.put_configuration_recorder(ConfigurationRecorder=recorder)
            )
            ctx.on_cleanup(
                lambda: _retry_throttled(
                    lambda: cfg.delete_configuration_recorder(
                        ConfigurationRecorderName=name
                    )
                )
            )
            return name
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in (
                "InsufficientPermissionsException",
                "AccessDeniedException",
            ) or time.monotonic() >= deadline:
                raise
            time.sleep(2.0)


def _put_recording_group(ctx, name, recording_group, role_arn):
    """Re-put an EXISTING recorder with a different recordingGroup. No cleanup is registered:
    the recorder's delete is already registered by the _create_recorder that made it."""
    cfg = ctx.client("config")
    _retry_throttled(
        lambda: cfg.put_configuration_recorder(
            ConfigurationRecorder={
                "name": name,
                "roleARN": role_arn,
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
    _retry_throttled(
        lambda: cfg.start_configuration_recorder(ConfigurationRecorderName=name)
    )
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
    _retry_throttled(
        lambda: cfg.stop_configuration_recorder(ConfigurationRecorderName=name)
    )
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
    """Create a delivery bucket with the Config delivery policy, a delivery channel and a
    running recorder. Returns (recorder, channel, bucket)."""
    _clear_recorders(ctx)
    _clear_delivery_channels(ctx)
    bucket = _create_delivery_bucket(ctx, scenario)
    # The recorder's service role is created here and deleted at cleanup, so no recorder depends
    # on a role that some other run left in the account.
    _role_name, role_arn = _create_role(
        ctx,
        "sim2real-behav-cfg-recorder-role-",
        "config.amazonaws.com",
        scenario,
        managed_policies=(_CONFIG_MANAGED_POLICY_ARN,),
    )
    recorder = ctx.unique_name("sim2real-behav-cfg-recorder-")
    _create_recorder(ctx, recorder, role_arn, recording_group=recording_group)
    channel = ctx.unique_name("sim2real-behav-cfg-channel-")
    _create_delivery_channel(ctx, channel, bucket)
    _start_recorder(ctx, recorder)
    return recorder, channel, bucket


def _await_history_items(
    ctx, resource_type, resource_id, *, timeout_s, predicate=None, description=None
):
    """Poll for configuration items; on timeout, report the recorder's own status so a stalled
    recorder is distinguishable from an unrecorded resource."""
    predicate = predicate or (lambda items: bool(items))
    description = (
        description or f"a configuration item for {resource_type} {resource_id!r}"
    )
    deadline = time.monotonic() + _capped(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = _retry_throttled(lambda: _history_items(ctx, resource_type, resource_id))
        if predicate(last):
            return last
        time.sleep(2.0)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}. Recorder status: "
        f"{_all_recorder_statuses(ctx)!r}"
    )


def _all_recorder_statuses(ctx):
    cfg = ctx.client("config")
    try:
        return [
            {
                k: s.get(k)
                for k in (
                    "name",
                    "recording",
                    "lastStatus",
                    "lastErrorCode",
                    "lastErrorMessage",
                )
            }
            for s in cfg.describe_configuration_recorder_status()[
                "ConfigurationRecordersStatus"
            ]
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
        if (
            exc.response.get("Error", {}).get("Code")
            == "ResourceNotDiscoveredException"
        ):
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
    propagating. For POLLING only - the negative leg asserts through _refusal instead."""
    cfg = ctx.client("config")
    try:
        return cfg.start_remediation_execution(
            ConfigRuleName=rule_name, ResourceKeys=resource_keys
        )
    except ClientError as exc:
        if (
            exc.response.get("Error", {}).get("Code")
            == "NoSuchRemediationConfigurationException"
        ):
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
        qual = r.get("EvaluationResultIdentifier", {}).get(
            "EvaluationResultQualifier", {}
        )
        if qual.get("ResourceId") == resource_id:
            return r
    return None


def _bucket_keys(ctx, bucket):
    s3 = ctx.client("s3")
    keys = []
    for page in s3.get_paginator("list_objects_v2").paginate(Bucket=bucket):
        keys.extend(o["Key"] for o in page.get("Contents", []))
    return keys


CHECK = "config-stopped-recorder-records-no-configuration-item-until-restarted"
GROUP = "configuration-recorder"
SERVICES = ["config", "sqs"]


@tags(
    "axis:negative-delivery",
    "cap:c7",
    "concern:data-plane",
    "concern:e2e",
    "concern:negative-classes",
    "dp:api",
    "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder",
)
def run(ctx) -> None:
    """After StopConfigurationRecorder, a new queue gets no configuration item
    (ResourceNotDiscoveredException); a restart does not backfill it, and a further change to that
    queue is then recorded as its only snapshot.
    """
    _restore_config_recorder_on_teardown(ctx)
    scenario = "config-stopped-recorder-absence"

    recorder, _channel, _bucket = _start_recording(ctx, scenario)

    # --- calibration barrier: how long does THIS account take to record a queue right now? ---
    calib_name, calib_url = _create_queue(
        ctx, scenario, attributes={"VisibilityTimeout": "137"}
    )
    t_calib = time.monotonic()
    calib_items = _await_history_items(
        ctx,
        "AWS::SQS::Queue",
        calib_url,
        timeout_s=1500,
        description=f"the calibration configuration item for queue {calib_url!r}",
    )
    latency_s = time.monotonic() - t_calib
    assert calib_items, (
        "the calibration barrier failed: the RUNNING recorder produced no item for a queue, so an "
        "absence measured later would prove nothing about the stop"
    )

    # --- break exactly one thing: stop the recorder ---
    _stop_recorder(ctx, recorder)

    absent_name, absent_url = _create_queue(
        ctx, scenario, attributes={"VisibilityTimeout": "141"}
    )

    # Hold the absence for a window calibrated to the latency the RUNNING recorder just needed
    # (floored so a fast account still gets a real window, capped to bound runtime): a target
    # that silently kept recording would otherwise pass this check for free, since discovery
    # takes latency_s even when the recorder is on and an immediate read never gives it the
    # chance to prove the resource undiscovered.
    window_s = _capped(ctx, min(max(3.0 * latency_s, 180.0), 480.0))
    deadline = time.monotonic() + window_s
    samples = 0
    code = message = None
    while True:
        code, message = _refusal(
            lambda: ctx.client("config").get_resource_config_history(
                resourceType="AWS::SQS::Queue", resourceId=absent_url
            )
        )
        assert code == "ResourceNotDiscoveredException", (
            f"expected the queue created under a stopped recorder to be undiscovered, got "
            f"{code!r} (the running recorder had recorded a queue in {latency_s:.0f}s, and the "
            f"absence was watched for {window_s:.0f}s)"
        )
        samples += 1
        if time.monotonic() >= deadline:
            break
        time.sleep(min(15.0, max(1.0, window_s / 6)))
    assert samples >= 3, (
        f"the absence window took too few samples to be meaningful: {samples}"
    )
    assert message == (
        f"Resource {absent_url} of resourceType:AWS::SQS::Queue is unknown or has not been "
        f"discovered"
    ), f"the refusal must be Config's exact not-discovered message, got {message!r}"

    # --- repair the one broken thing, then prove the SAME queue was recordable all along ---
    restart_at = datetime.datetime.now(datetime.timezone.utc)
    _start_recorder(ctx, recorder, register_cleanup=False)

    # A restart does not re-baseline an SQS queue whose creation the recorder missed (it stays
    # undiscovered for many minutes), so the control is a fresh change to that same queue.
    ctx.client("sqs").set_queue_attributes(
        QueueUrl=absent_url, Attributes={"VisibilityTimeout": "151"}
    )
    resumed = _await_history_items(
        ctx,
        "AWS::SQS::Queue",
        absent_url,
        timeout_s=480,
        description=f"queue {absent_url!r} is recorded once the recorder runs again and it changes",
    )
    assert resumed, (
        f"the control failed: queue {absent_name!r} was never recorded even after the recorder was "
        f"restarted AND the queue was changed, so its earlier absence is not evidence about "
        f"StopConfigurationRecorder"
    )
    # Absence by contrast: the history that holds the post-restart change holds no snapshot of the
    # queue as created while the recorder was stopped.
    timeouts = [json.loads(i["configuration"])["VisibilityTimeout"] for i in resumed]
    assert "141" not in timeouts, (
        f"a stopped recorder recorded queue {absent_name!r} as created (VisibilityTimeout 141): "
        f"history VisibilityTimeouts {timeouts!r}"
    )
    assert json.loads(resumed[0]["configuration"])["VisibilityTimeout"] == "151", (
        f"the resumed recording is not a snapshot of the changed queue: "
        f"{resumed[0]['configuration']!r}"
    )
    assert resumed[0]["resourceName"] == absent_name, (
        f"the resumed item describes a different queue: {resumed[0]['resourceName']!r} != "
        f"{absent_name!r}"
    )
    # Nothing was backfilled for the window in which the recorder was stopped.
    assert all(i["configurationItemCaptureTime"] > restart_at for i in resumed), (
        f"Config retroactively recorded the stopped window: capture times "
        f"{[i['configurationItemCaptureTime'] for i in resumed]!r} against a restart at "
        f"{restart_at!r}"
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
