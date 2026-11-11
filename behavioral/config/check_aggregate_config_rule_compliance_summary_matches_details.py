"""aggregate-config-rule-compliance-summary-matches-details."""
from __future__ import annotations

import io
import json
import time
import zipfile

from behavioral_harness import tags

CHECK = "aggregate-config-rule-compliance-summary-matches-details"
GROUP = "data-plane"
SERVICES = ["config"]

_OVERALL_BUDGET_S = 260.0  # stay under the harness's ~300s per-check wall-clock cap


@tags("axis:happy-path", "cap:c2", "cap:c3", "concern:data-plane", "dp:api", "plane:data", "resource:account-singleton:config-aggregation-authorization", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """After a new Lambda-backed rule reports a NON_COMPLIANT evaluation through PutEvaluations,
    GetAggregateComplianceDetailsByConfigRule returns exactly one NON_COMPLIANT result for it, qualified
    with the evaluated resource's id."""
    _restore_config_recorder_on_teardown(ctx)
    config = ctx.client("config")
    start = time.monotonic()
    deadline = start + _OVERALL_BUDGET_S

    rule_name = ctx.unique_name("sim2real-summary-rule-")

    _ensure_recorder_exists(ctx)

    account_id, region = _setup_self_aggregator(ctx, ctx.unique_name("sim2real-agg-"))
    aggregator_name = _LAST_AGGREGATOR["name"]

    baseline = _noncompliant_count(config, aggregator_name, account_id, region)

    # The evaluated "resource" is this run's own Lambda function: AWS Config's
    # PutEvaluations rejects a made-up ComplianceResourceType with
    # InvalidParameterValueException, so the reported resource must be a type
    # Config recognizes, and using a real, per-run-unique resource this check
    # already owns avoids colliding with concurrent runs.
    lambda_arn, resource_id = _create_evaluating_lambda(ctx, "NON_COMPLIANT")
    _create_scheduled_lambda_rule(ctx, rule_name, lambda_arn)
    # A brand-new rule is auto-evaluated by Config on creation; this on-demand
    # trigger just avoids waiting for that to happen on its own schedule.
    _retry_on(
        lambda: config.start_config_rules_evaluation(ConfigRuleNames=[rule_name]),
        ("ResourceInUseException", "NoSuchConfigRuleException", "LimitExceededException"),
        timeout_s=45,
        interval_s=5,
    )

    local_budget = max(30.0, (deadline - time.monotonic()) * 0.55)
    local_details = _poll_until(
        lambda: config.get_compliance_details_by_config_rule(ConfigRuleName=rule_name)[
            "EvaluationResults"
        ],
        lambda results: len(results) > 0,
        timeout_s=local_budget,
        interval_s=8,
    )
    if not local_details:
        raise AssertionError(
            f"the Lambda-backed rule never delivered a PutEvaluations result within "
            f"{local_budget:.0f}s; AWS Config's first evaluation of a brand-new custom "
            "Lambda rule can take longer than this check's time budget allows in this "
            "environment."
        )
    assert local_details[0]["ComplianceType"] == "NON_COMPLIANT", (
        f"expected the rule's own compliance detail to be NON_COMPLIANT, got "
        f"{local_details[0]['ComplianceType']!r}"
    )

    aggregate_budget = max(20.0, deadline - time.monotonic() - 30)
    after = _poll_until(
        lambda: _noncompliant_count(config, aggregator_name, account_id, region),
        lambda n: n == baseline + 1,
        timeout_s=aggregate_budget,
        interval_s=8,
    )
    if after != baseline + 1:
        raise AssertionError(
            "the local evaluation result was observed, but the aggregator's "
            f"non-compliant-rule count never grew by exactly 1 within {aggregate_budget:.0f}s "
            f"(baseline={baseline}, observed={after}); aggregation propagation lag exceeded "
            "this check's remaining time budget."
        )

    # The aggregate summary count and the aggregate per-resource detail rows are
    # indexed on independent paths, so the count can move before the detail row
    # is queryable — poll the detail read too instead of trusting the count's
    # own timing.
    detail_budget = max(30.0, deadline - time.monotonic())
    aggregate_details = _poll_until(
        lambda: config.get_aggregate_compliance_details_by_config_rule(
            ConfigurationAggregatorName=aggregator_name,
            ConfigRuleName=rule_name,
            AccountId=account_id,
            AwsRegion=region,
        )["AggregateEvaluationResults"],
        lambda results: len(results) > 0,
        timeout_s=detail_budget,
        interval_s=5,
    ) or []
    assert len(aggregate_details) == 1, (
        f"expected exactly 1 aggregate evaluation result for {rule_name!r}, got "
        f"{len(aggregate_details)}: {aggregate_details!r}"
    )
    assert aggregate_details[0]["ComplianceType"] == "NON_COMPLIANT", (
        f"expected the aggregate evaluation result to be NON_COMPLIANT, got "
        f"{aggregate_details[0]['ComplianceType']!r}"
    )
    qualifier = aggregate_details[0]["EvaluationResultIdentifier"]["EvaluationResultQualifier"]
    assert qualifier["ResourceId"] == resource_id, (
        f"expected the aggregate evaluation result to be keyed to {resource_id!r}, got "
        f"{qualifier['ResourceId']!r}"
    )


_LAST_AGGREGATOR: dict = {}


def _noncompliant_count(config, aggregator_name, account_id, region):
    resp = config.get_aggregate_config_rule_compliance_summary(
        ConfigurationAggregatorName=aggregator_name,
        Filters={"AccountId": account_id, "AwsRegion": region},
    )
    counts = resp.get("AggregateComplianceCounts", [])
    if not counts:
        return 0
    return counts[0]["ComplianceSummary"]["NonCompliantResourceCount"]["CappedCount"]


def _setup_self_aggregator(ctx, aggregator_name):
    config = ctx.client("config")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    region = ctx.region

    config.put_aggregation_authorization(
        AuthorizedAccountId=account_id,
        AuthorizedAwsRegion=region,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
    """Custom Lambda rule evaluations are only dispatched while the account's
    configuration recorder is actively recording (not merely present), and
    StartConfigurationRecorder itself refuses without a delivery channel — so
    both must be adopted-or-created and the recorder started, not just put."""
    config = ctx.client("config")
    iam = ctx.client("iam")

    recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if recorders:
        recorder_name = recorders[0]["name"]
    else:
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
        # registered first so it runs after the policy detaches and deletes below
        ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
        iam.attach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
        )
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
                },
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            ),
            ("InvalidRoleException",),
            timeout_s=60,
            interval_s=5,
        )
        ctx.on_cleanup(
            lambda: config.delete_configuration_recorder(ConfigurationRecorderName=recorder_name)
        )

    _ensure_recorder_started(ctx, recorder_name)
    return recorder_name


def _ensure_recorder_started(ctx, recorder_name):
    config = ctx.client("config")
    status = config.describe_configuration_recorder_status(
        ConfigurationRecorderNames=[recorder_name]
    )["ConfigurationRecordersStatus"][0]
    if status.get("recording"):
        return
    _ensure_delivery_channel_exists(ctx)
    config.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
    ctx.on_cleanup(
        lambda: config.stop_configuration_recorder(ConfigurationRecorderName=recorder_name)
    )


def _ensure_delivery_channel_exists(ctx):
    config = ctx.client("config")
    channels = config.describe_delivery_channels().get("DeliveryChannels", [])
    if channels:
        return channels[0]["name"]

    s3 = ctx.client("s3")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket_name = ctx.unique_name("sim2real-cfg-bucket-").lower()
    # us-east-1 is S3's own legacy region and CreateBucket rejects a
    # LocationConstraint there, regardless of ctx.region — not a check-region pin.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(
            Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    s3.put_bucket_tagging(
        Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )
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

    channel_name = ctx.unique_name("sim2real-cfg-channel-")
    _retry_on(
        lambda: config.put_delivery_channel(
            DeliveryChannel={"name": channel_name, "s3BucketName": bucket_name}
        ),
        ("InsufficientDeliveryPolicyException",),
        timeout_s=60,
        interval_s=5,
    )
    ctx.on_cleanup(lambda: config.delete_delivery_channel(DeliveryChannelName=channel_name))
    return channel_name


def _empty_and_delete_bucket(s3, bucket_name):
    objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
    if objs:
        failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
        if failed:
            raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    s3.delete_bucket(Bucket=bucket_name)


def _create_evaluating_lambda(ctx, compliance_type):
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    function_name = ctx.unique_name("sim2real-evalfn-")

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
    # registered first so it runs after the policy detaches and deletes below
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
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
        "            'ComplianceResourceType': 'AWS::Lambda::Function',\n"
        f"            'ComplianceResourceId': {function_name!r},\n"
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

    fn = _retry_on(_create_function, ("InvalidParameterValueException",), timeout_s=60, interval_s=5)
    function_arn = fn["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=function_name))

    lam.get_waiter("function_active_v2").wait(FunctionName=function_name, WaiterConfig={"Delay": 2, "MaxAttempts": 150})

    lam.add_permission(
        FunctionName=function_name,
        StatementId="AllowConfigInvoke",
        Action="lambda:InvokeFunction",
        Principal="config.amazonaws.com",
    )
    return function_arn, function_name


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
        interval_s=5,
    )
    ctx.on_cleanup(lambda: config.delete_config_rule(ConfigRuleName=rule_name))


def _retry_on(fn, error_codes, *, timeout_s=30.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            response = getattr(exc, "response", None)
            code = response.get("Error", {}).get("Code") if response else None
            if code not in error_codes or time.monotonic() >= deadline:
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
