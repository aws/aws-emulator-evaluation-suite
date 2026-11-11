"""aggregate-compliance-details-reflect-source-rule-evaluation."""
from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags

CHECK = "aggregate-compliance-details-reflect-source-rule-evaluation"
GROUP = "data-plane"
SERVICES = ["config"]

# PutEvaluations rejects resource types Config does not support with
# InvalidParameterValueException, which looks like the evaluation never landing. AWS::::Account
# is Config's account-wide pseudo-resource type; its ResourceId is the account id.
_RESOURCE_TYPE = "AWS::::Account"
_OVERALL_BUDGET_S = 900.0


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "concern:representation", "dp:api", "plane:data", "resource:account-singleton:config-aggregation-authorization", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """GetAggregateComplianceDetailsByConfigRule on a self-aggregator surfaces the evaluation a
    Lambda-backed rule delivered via PutEvaluations, with the same ResourceId, ResourceType and
    ComplianceType that GetComplianceDetailsByConfigRule reports locally."""
    _restore_config_recorder_on_teardown(ctx)
    config = ctx.client("config")
    start = time.monotonic()
    wall_start = datetime.now(timezone.utc)
    deadline = start + _OVERALL_BUDGET_S

    # The evaluated resource is the account itself (see _RESOURCE_TYPE).
    resource_id = ctx.client("sts").get_caller_identity()["Account"]
    compliance_type = "NON_COMPLIANT"
    rule_name = ctx.unique_name("sim2real-agg-rule-")

    _ensure_recorder_exists(ctx)
    lambda_arn = _create_evaluating_lambda(ctx, resource_id, compliance_type)
    _create_scheduled_lambda_rule(ctx, rule_name, lambda_arn)

    account_id, region = _setup_self_aggregator(ctx, ctx.unique_name("sim2real-agg-"))
    aggregator_name = _LAST_AGGREGATOR["name"]

    # A brand-new rule is auto-evaluated by Config on creation; this on-demand
    # trigger just avoids waiting for that to happen on its own schedule.
    _retry_on(
        lambda: config.start_config_rules_evaluation(ConfigRuleNames=[rule_name]),
        ("ResourceInUseException", "NoSuchConfigRuleException", "LimitExceededException"),
        timeout_s=_budget_s(ctx, 45),
        interval_s=2,
        ctx=ctx,
    )

    # A self-aggregator reads the source account's own already-computed evaluation, so once
    # the local result exists the aggregate side converges quickly; the first scheduled
    # evaluation of a brand-new custom Lambda rule is the bottleneck, so it gets most of the
    # remaining time.
    local_budget = max(30.0, (deadline - time.monotonic()) * 0.85)
    local_result = _poll_until(
        lambda: _find_local_result(config, rule_name, resource_id),
        lambda r: r is not None,
        timeout_s=_budget_s(ctx, local_budget),
        interval_s=2,
    )
    if local_result is None and _budget_spent(ctx):
        raise TimeoutError("the Lambda-backed rule's PutEvaluations result: the run budget ended first; not graded")
    if local_result is None:
        invocations, errors = _lambda_invocation_counts(ctx, lambda_arn, wall_start)
        log_tail = _lambda_error_log_tail(ctx, lambda_arn, wall_start) if errors else ""
        raise AssertionError(
            f"the Lambda-backed rule never delivered a PutEvaluations result within "
            f"{local_budget:.0f}s; AWS Config's first evaluation of a brand-new custom "
            "Lambda rule can take longer than this check's time budget allows in this "
            f"environment. CloudWatch reports {invocations:.0f} Invocations and "
            f"{errors:.0f} Errors for the rule's Lambda in that window.{log_tail}"
        )
    assert local_result["ComplianceType"] == compliance_type, (
        f"expected local ComplianceType {compliance_type!r}, got "
        f"{local_result['ComplianceType']!r}: {local_result!r}"
    )

    aggregate_budget = max(20.0, deadline - time.monotonic() - 5)
    aggregate_result = _poll_until(
        lambda: _find_aggregate_result(
            config, aggregator_name, rule_name, resource_id, account_id, region
        ),
        lambda r: r is not None,
        timeout_s=_budget_s(ctx, aggregate_budget),
        interval_s=2,
    )
    if aggregate_result is None and _budget_spent(ctx):
        raise TimeoutError("the self-aggregator surfacing the local evaluation: the run budget ended first; not graded")
    if aggregate_result is None:
        raise AssertionError(
            "the local evaluation result was observed, but the (self-)aggregator did "
            f"not surface it within {aggregate_budget:.0f}s; cross-account aggregation "
            "propagation lag exceeded this check's remaining time budget."
        )
    qualifier = aggregate_result["EvaluationResultIdentifier"]["EvaluationResultQualifier"]
    assert qualifier["ResourceId"] == resource_id, (
        f"expected aggregate ResourceId {resource_id!r}, got {qualifier['ResourceId']!r}"
    )
    assert qualifier["ResourceType"] == _RESOURCE_TYPE, (
        f"expected aggregate ResourceType {_RESOURCE_TYPE!r}, got {qualifier['ResourceType']!r}"
    )
    assert aggregate_result["ComplianceType"] == compliance_type, (
        f"expected aggregate ComplianceType {compliance_type!r}, got "
        f"{aggregate_result['ComplianceType']!r}"
    )
    assert aggregate_result["ComplianceType"] == local_result["ComplianceType"], (
        f"aggregate ComplianceType {aggregate_result['ComplianceType']!r} diverges from "
        f"local ComplianceType {local_result['ComplianceType']!r} for the same resource"
    )


_LAST_AGGREGATOR: dict = {}


def _lambda_invocation_counts(ctx, lambda_arn, since):
    """Diagnostic for the timeout path: Lambda Invocations and Errors sums, to tell "never
    invoked" from "invoked but errored" from "succeeded but slow to surface"."""
    cw = ctx.client("cloudwatch")
    function_name = lambda_arn.split(":")[-1]
    end = datetime.now(timezone.utc)
    period = max(60, 60 * ((int((end - since).total_seconds()) + 59) // 60))

    def _sum(metric_name):
        stats = cw.get_metric_statistics(
            Namespace="AWS/Lambda",
            MetricName=metric_name,
            Dimensions=[{"Name": "FunctionName", "Value": function_name}],
            StartTime=since - timedelta(minutes=1),
            EndTime=end,
            Period=period,
            Statistics=["Sum"],
        )
        return sum(p["Sum"] for p in stats.get("Datapoints", []))

    return _sum("Invocations"), _sum("Errors")


def _lambda_error_log_tail(ctx, lambda_arn, since):
    """Diagnostic: recent error lines from the Lambda's log group, to tell a handler bug from
    AWS-side lag in a timeout report."""
    logs = ctx.client("logs")
    function_name = lambda_arn.split(":")[-1]
    start_ms = int((since - timedelta(minutes=1)).timestamp() * 1000)
    try:
        events = logs.filter_log_events(
            logGroupName=f"/aws/lambda/{function_name}",
            startTime=start_ms,
            filterPattern="?Error ?Exception ?Traceback",
            limit=10,
        ).get("events", [])
    except logs.exceptions.ResourceNotFoundException:
        return " (no log group found)"
    if not events:
        return " (no matching log lines)"
    return " Log tail: " + " | ".join(e["message"].strip() for e in events[-5:])


def _find_local_result(config, rule_name, resource_id):
    resp = config.get_compliance_details_by_config_rule(ConfigRuleName=rule_name)
    for result in resp.get("EvaluationResults", []):
        qualifier = result["EvaluationResultIdentifier"]["EvaluationResultQualifier"]
        if qualifier.get("ResourceId") == resource_id:
            return result
    return None


def _find_aggregate_result(config, aggregator_name, rule_name, resource_id, account_id, region):
    resp = config.get_aggregate_compliance_details_by_config_rule(
        ConfigurationAggregatorName=aggregator_name,
        ConfigRuleName=rule_name,
        AccountId=account_id,
        AwsRegion=region,
    )
    for result in resp.get("AggregateEvaluationResults", []):
        qualifier = result["EvaluationResultIdentifier"]["EvaluationResultQualifier"]
        if qualifier.get("ResourceId") == resource_id:
            return result
    return None


def _setup_self_aggregator(ctx, aggregator_name):
    config = ctx.client("config")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    config.put_aggregation_authorization(
        AuthorizedAccountId=account_id, AuthorizedAwsRegion=region
    )
    ctx.on_cleanup(
        lambda: config.delete_aggregation_authorization(
            AuthorizedAccountId=account_id, AuthorizedAwsRegion=region
        )
    )
    config.put_configuration_aggregator(
        ConfigurationAggregatorName=aggregator_name,
        AccountAggregationSources=[
            {"AccountIds": [account_id], "AllAwsRegions": False, "AwsRegions": [region]}
        ],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: config.delete_configuration_aggregator(
            ConfigurationAggregatorName=aggregator_name
        )
    )
    _LAST_AGGREGATOR["name"] = aggregator_name
    return account_id, region


def _ensure_recorder_exists(ctx):
    """Ensure a RECORDING configuration recorder: rule evaluation never happens with a stopped
    one. Reuses (and starts) an existing recorder without stopping it later; only cleans up a
    recorder this check created."""
    config = ctx.client("config")
    iam = ctx.client("iam")

    recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if recorders:
        name = recorders[0]["name"]
        status = config.describe_configuration_recorder_status(
            ConfigurationRecorderNames=[name]
        )["ConfigurationRecordersStatus"][0]
        if not status.get("recording"):
            config.start_configuration_recorder(ConfigurationRecorderName=name)
        return name

    role_name = ctx.unique_name("sim2real-cfgrole-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
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
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
        )
    )

    recorder_name = "default"
    _retry_on(
        lambda: config.put_configuration_recorder(
            ConfigurationRecorder={
                "name": recorder_name,
                "roleARN": role_arn,
                "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
            }
        ),
        ("InvalidRoleException",),
        timeout_s=60,
        interval_s=2,
    )
    ctx.on_cleanup(
        lambda: config.delete_configuration_recorder(ConfigurationRecorderName=recorder_name)
    )

    # StartConfigurationRecorder requires a delivery channel to exist -- an account with
    # zero pre-existing recorders (the only way this branch is reached) also has zero
    # delivery channels.
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bucket_name = ctx.unique_name("sim2real-cfgrole-bucket-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_policy(
        Bucket=bucket_name,
        Policy=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Sid": "AWSConfigBucketPermissionsCheck",
                        "Effect": "Allow",
                        "Principal": {"Service": "config.amazonaws.com"},
                        "Action": "s3:GetBucketAcl",
                        "Resource": f"arn:aws:s3:::{bucket_name}",
                    },
                    {
                        "Sid": "AWSConfigBucketExistenceCheck",
                        "Effect": "Allow",
                        "Principal": {"Service": "config.amazonaws.com"},
                        "Action": "s3:ListBucket",
                        "Resource": f"arn:aws:s3:::{bucket_name}",
                    },
                    {
                        "Sid": "AWSConfigBucketDelivery",
                        "Effect": "Allow",
                        "Principal": {"Service": "config.amazonaws.com"},
                        "Action": "s3:PutObject",
                        "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/Config/*",
                        "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}},
                    },
                ],
            }
        ),
    )
    # The config role's trust policy was only just created; Config's own attempt to assume it
    # (to validate delivery) can lag IAM's propagation by a few seconds, surfacing as the same
    # InsufficientDeliveryPolicyException a genuinely wrong policy would raise.
    _retry_on(
        lambda: config.put_delivery_channel(
            DeliveryChannel={"name": recorder_name, "s3BucketName": bucket_name}
        ),
        ("InsufficientDeliveryPolicyException",),
        timeout_s=60,
        interval_s=2,
    )
    ctx.on_cleanup(lambda: config.delete_delivery_channel(DeliveryChannelName=recorder_name))

    config.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
    ctx.on_cleanup(
        lambda: config.stop_configuration_recorder(ConfigurationRecorderName=recorder_name)
    )
    return recorder_name


def _empty_and_delete_bucket(s3, bucket_name):
    objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
    if objs:
        failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


def _create_evaluating_lambda(ctx, resource_id, compliance_type):
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-lambdarole-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Principal": {"Service": "lambda.amazonaws.com"},
                        "Action": "sts:AssumeRole",
                    }
                ],
            }
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
    )
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="ConfigPutEvaluations",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [{"Effect": "Allow", "Action": "config:PutEvaluations", "Resource": "*"}],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name,
            PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole",
        )
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="ConfigPutEvaluations"))

    source = (
        "import boto3\n"
        "from datetime import datetime, timezone\n"
        "def handler(event, context):\n"
        "    client = boto3.client('config')\n"
        "    client.put_evaluations(\n"
        "        Evaluations=[{\n"
        f"            'ComplianceResourceType': {_RESOURCE_TYPE!r},\n"
        f"            'ComplianceResourceId': {resource_id!r},\n"
        f"            'ComplianceType': {compliance_type!r},\n"
        "            'OrderingTimestamp': datetime.now(timezone.utc),\n"
        "        }],\n"
        "        ResultToken=event['resultToken'],\n"
        "    )\n"
        "    return {'statusCode': 200}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", source)

    function_name = ctx.unique_name("sim2real-evalfn-")

    def _create_function():
        return lam.create_function(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": buf.getvalue()},
            Timeout=15,
            Tags={"sim2real-check": CHECK},
        )

    fn = _retry_on(_create_function, ("InvalidParameterValueException",), timeout_s=60, interval_s=2)
    function_arn = fn["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))

    lam.get_waiter("function_active_v2").wait(
        FunctionName=function_name, WaiterConfig={"Delay": 1, "MaxAttempts": 300}
    )

    lam.add_permission(
        FunctionName=function_name,
        StatementId="AllowConfigInvoke",
        Action="lambda:InvokeFunction",
        Principal="config.amazonaws.com",
    )
    return function_arn


def _create_scheduled_lambda_rule(ctx, rule_name, lambda_arn):
    config = ctx.client("config")

    _retry_on(
        lambda: config.put_config_rule(
            ConfigRule={
                "ConfigRuleName": rule_name,
                "Source": {
                    "Owner": "CUSTOM_LAMBDA",
                    "SourceIdentifier": lambda_arn,
                    "SourceDetails": [
                        {
                            "EventSource": "aws.config",
                            "MessageType": "ScheduledNotification",
                            "MaximumExecutionFrequency": "TwentyFour_Hours",
                        }
                    ],
                },
                "MaximumExecutionFrequency": "TwentyFour_Hours",
            },
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        ),
        ("InsufficientPermissionsException",),
        timeout_s=60,
        interval_s=2,
    )
    ctx.on_cleanup(lambda: config.delete_config_rule(ConfigRuleName=rule_name))


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _retry_on(fn, error_codes, *, timeout_s=30.0, interval_s=3.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            response = getattr(exc, "response", None)
            code = response.get("Error", {}).get("Code") if response else None
            if code not in error_codes or time.monotonic() >= deadline:
                if code in error_codes and ctx is not None and _budget_spent(ctx):
                    raise TimeoutError(f"retry past {code}: the run budget ended first; not graded") from exc
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    return last if last is not None and predicate(last) else None


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
