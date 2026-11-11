"""aggregate-compliance-summary-reflects-source-evaluations."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "aggregate-compliance-summary-reflects-source-evaluations"
GROUP = "data-plane"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c2", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A NON_COMPLIANT evaluation a custom Lambda rule submits via PutEvaluations shows up in a
    self-aggregator's GetAggregateComplianceDetailsByConfigRule and raises the source account's
    non-compliant count in GetAggregateConfigRuleComplianceSummary by one."""
    _restore_config_recorder_on_teardown(ctx)
    config = ctx.client("config")
    lam = ctx.client("lambda")
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-cfg-lambda-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"))
    inline_policy_name = "put-evaluations"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "config:PutEvaluations", "Resource": "*"}]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name))

    code = (
        "import boto3, os\n"
        "from datetime import datetime, timezone\n"
        "def handler(event, context):\n"
        "    token = event.get('resultToken')\n"
        "    if not token:\n"
        "        return {'skipped': True}\n"
        "    client = boto3.client('config')\n"
        "    client.put_evaluations(\n"
        "        Evaluations=[{\n"
        "            'ComplianceResourceType': 'AWS::::Account',\n"
        "            'ComplianceResourceId': os.environ['ACCOUNT_ID'],\n"
        "            'ComplianceType': 'NON_COMPLIANT',\n"
        "            'Annotation': 'sim2real-behavioral-check',\n"
        "            'OrderingTimestamp': datetime.now(timezone.utc),\n"
        "        }],\n"
        "        ResultToken=token,\n"
        "    )\n"
        "    return {'ok': True}\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    zip_bytes = buf.getvalue()

    fn_name = ctx.unique_name("sim2real-cfg-rule-fn-")
    deadline = time.monotonic() + 90
    fn_arn = None
    while fn_arn is None:
        try:
            resp = lam.create_function(
                FunctionName=fn_name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=30,
                Environment={"Variables": {"ACCOUNT_ID": account_id}},
            )
            fn_arn = resp["FunctionArn"]
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=fn_name))

    waiter = lam.get_waiter("function_active_v2")
    waiter.wait(FunctionName=fn_name, WaiterConfig={"Delay": 1, "MaxAttempts": 120})

    lam.add_permission(
        FunctionName=fn_name,
        StatementId="ConfigInvoke",
        Action="lambda:InvokeFunction",
        Principal="config.amazonaws.com",
        SourceAccount=account_id,
    )

    _ensure_recorder_and_channel(ctx)

    agg_name = ctx.unique_name("sim2real-cfg-agg-")
    config.put_configuration_aggregator(
        ConfigurationAggregatorName=agg_name,
        AccountAggregationSources=[{"AccountIds": [account_id], "AllAwsRegions": False, "AwsRegions": [ctx.region]}],
    )
    ctx.on_cleanup(lambda: config.delete_configuration_aggregator(ConfigurationAggregatorName=agg_name))

    def _summary_noncompliant_count():
        resp = config.get_aggregate_config_rule_compliance_summary(
            ConfigurationAggregatorName=agg_name,
            Filters={"AccountId": account_id, "AwsRegion": ctx.region},
        )
        return sum(c["ComplianceSummary"]["NonCompliantResourceCount"]["CappedCount"] for c in resp["AggregateComplianceCounts"])

    baseline_noncompliant = _summary_noncompliant_count()

    rule_name = ctx.unique_name("sim2real-cfg-lambda-rule-")
    config.put_config_rule(
        ConfigRule={
            "ConfigRuleName": rule_name,
            "Source": {
                "Owner": "CUSTOM_LAMBDA",
                "SourceIdentifier": fn_arn,
                "SourceDetails": [{"EventSource": "aws.config", "MessageType": "ScheduledNotification", "MaximumExecutionFrequency": "TwentyFour_Hours"}],
            },
            "MaximumExecutionFrequency": "TwentyFour_Hours",
        }
    )
    ctx.on_cleanup(lambda: _delete_config_rule(config, rule_name))

    _poll_until(
        lambda: config.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"][0]["ConfigRuleState"],
        lambda state: state == "ACTIVE",
        ctx=ctx,
        timeout_s=90,
    )

    _trigger_evaluation(config, rule_name)

    def _has_non_compliant_result():
        results = config.get_compliance_details_by_config_rule(ConfigRuleName=rule_name)["EvaluationResults"]
        return any(
            r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"] == account_id
            and r["ComplianceType"] == "NON_COMPLIANT"
            for r in results
        )

    _poll_until(lambda: _has_non_compliant_result(), lambda ok: ok, ctx=ctx, timeout_s=120)

    def _aggregate_detail_matches():
        resp = config.get_aggregate_compliance_details_by_config_rule(
            ConfigurationAggregatorName=agg_name,
            ConfigRuleName=rule_name,
            AccountId=account_id,
            AwsRegion=ctx.region,
        )
        return any(
            r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"] == account_id
            and r["ComplianceType"] == "NON_COMPLIANT"
            for r in resp["AggregateEvaluationResults"]
        )

    _poll_until(lambda: _aggregate_detail_matches(), lambda ok: ok, ctx=ctx, timeout_s=180)

    _poll_until(
        lambda: _summary_noncompliant_count(),
        lambda n: n == baseline_noncompliant + 1,
        ctx=ctx,
        timeout_s=90,
    )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, *, ctx, timeout_s=60.0, interval_s=1.0):
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    if _budget_spent(ctx):
        raise TimeoutError("the polled condition: the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _trigger_evaluation(config, rule_name):
    deadline = time.monotonic() + 30
    while True:
        try:
            config.start_config_rules_evaluation(ConfigRuleNames=[rule_name])
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise


def _delete_config_rule(config, rule_name):
    deadline = time.monotonic() + 60
    while True:
        try:
            config.delete_config_rule(ConfigRuleName=rule_name)
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "NoSuchConfigRuleException":
                return
            if code == "ResourceInUseException" and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _empty_and_delete_bucket(s3, bucket_name):
    try:
        objs = s3.list_objects_v2(Bucket=bucket_name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise
    s3.delete_bucket(Bucket=bucket_name)


def _ensure_recorder_and_channel(ctx):
    """Reuse an existing recorder (starting it if needed), or create a minimal one scoped to
    AWS::IAM::Role with a delivery channel: PutConfigRule requires a recorder in the account."""
    config = ctx.client("config")
    recorders = config.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if recorders:
        name = recorders[0]["name"]
        status = config.describe_configuration_recorder_status(ConfigurationRecorderNames=[name])["ConfigurationRecordersStatus"][0]
        if not status.get("recording"):
            config.start_configuration_recorder(ConfigurationRecorderName=name)
        return name

    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    role_name = ctx.unique_name("sim2real-cfg-recorder-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole")
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"))

    bucket_name = ctx.unique_name("sim2real-cfg-bucket-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(s3, bucket_name))
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Sid": "AWSConfigBucketPermissionsCheck", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "s3:GetBucketAcl", "Resource": f"arn:aws:s3:::{bucket_name}"},
            {"Sid": "AWSConfigBucketExistenceCheck", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "s3:ListBucket", "Resource": f"arn:aws:s3:::{bucket_name}"},
            {"Sid": "AWSConfigBucketDelivery", "Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "s3:PutObject", "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/Config/*", "Condition": {"StringEquals": {"s3:x-amz-acl": "bucket-owner-full-control"}}},
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))

    recorder_name = ctx.unique_name("sim2real-cfg-recorder-")
    deadline = time.monotonic() + 90
    while True:
        try:
            config.put_configuration_recorder(
                ConfigurationRecorder={
                    "name": recorder_name,
                    "roleARN": role_arn,
                    "recordingGroup": {"allSupported": False, "resourceTypes": ["AWS::IAM::Role"]},
                }
            )
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidRoleException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: config.delete_configuration_recorder(ConfigurationRecorderName=recorder_name))

    # Same IAM-propagation race as put_configuration_recorder above: Config assumes
    # role_arn to probe the bucket policy, and that assumption can fail for a few
    # seconds after the role/policy was just created.
    deadline = time.monotonic() + 60
    while True:
        try:
            config.put_delivery_channel(DeliveryChannel={"name": recorder_name, "s3BucketName": bucket_name})
            break
        except ClientError as e:
            if e.response["Error"]["Code"] == "InsufficientDeliveryPolicyException" and time.monotonic() < deadline:
                time.sleep(3)
                continue
            raise
    ctx.on_cleanup(lambda: config.delete_delivery_channel(DeliveryChannelName=recorder_name))

    config.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
    ctx.on_cleanup(lambda: config.stop_configuration_recorder(ConfigurationRecorderName=recorder_name))
    return recorder_name


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
