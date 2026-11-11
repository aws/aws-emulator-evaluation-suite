"""deploy-config-rule-cloudformation-evaluates-resource."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "deploy-config-rule-cloudformation-evaluates-resource"
GROUP = "deploy"
SERVICES = ["config"]

_LAMBDA_CODE = (
    "import json\n"
    "import datetime\n"
    "import boto3\n\n\n"
    "def handler(event, context):\n"
    "    config = boto3.client('config')\n"
    "    config.put_evaluations(\n"
    "        Evaluations=[{\n"
    "            'ComplianceResourceType': 'AWS::::Account',\n"
    "            'ComplianceResourceId': event['accountId'],\n"
    "            'ComplianceType': 'NON_COMPLIANT',\n"
    "            'Annotation': 'sim2real-cfn-deploy-check',\n"
    "            'OrderingTimestamp': datetime.datetime.utcnow(),\n"
    "        }],\n"
    "        ResultToken=event['resultToken'],\n"
    "    )\n"
    "    return 'done'\n"
)


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A ConfigRule deployed via CloudFormation is not just CREATE_COMPLETE: the
    stack's Lambda actually gets invoked and its PutEvaluations call produces a
    real, retrievable compliance record."""
    _restore_config_recorder_on_teardown(ctx)
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    _ensure_configuration_recorder(ctx)

    stack_name = ctx.unique_name("sim2real-config-rule-stack-")
    function_name = ctx.unique_name("sim2real-cfn-eval-")
    role_name = ctx.unique_name("sim2real-cfn-eval-role-")
    rule_name = ctx.unique_name("sim2real-cfn-rule-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "EvalRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
                        ],
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
                    "Policies": [
                        {
                            "PolicyName": "config-put-evaluations",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [{"Effect": "Allow", "Action": "config:PutEvaluations", "Resource": "*"}],
                            },
                        }
                    ],
                },
            },
            "EvalFunction": {
                "Type": "AWS::Lambda::Function",
                "DependsOn": "EvalRole",
                "Properties": {
                    "FunctionName": function_name,
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["EvalRole", "Arn"]},
                    "Timeout": 30,
                    "Code": {"ZipFile": _LAMBDA_CODE},
                },
            },
            "InvokePermission": {
                "Type": "AWS::Lambda::Permission",
                "Properties": {
                    "FunctionName": {"Ref": "EvalFunction"},
                    "Action": "lambda:InvokeFunction",
                    "Principal": "config.amazonaws.com",
                },
            },
            "EvalConfigRule": {
                "Type": "AWS::Config::ConfigRule",
                "DependsOn": "InvokePermission",
                "Properties": {
                    "ConfigRuleName": rule_name,
                    "Source": {
                        "Owner": "CUSTOM_LAMBDA",
                        "SourceIdentifier": {"Fn::GetAtt": ["EvalFunction", "Arn"]},
                        "SourceDetails": [
                            {
                                "EventSource": "aws.config",
                                "MessageType": "ScheduledNotification",
                                "MaximumExecutionFrequency": "TwentyFour_Hours",
                            }
                        ],
                    },
                },
            },
        },
    }

    _deploy_stack(ctx, stack_name, template)

    config = ctx.client("config")
    rules = config.describe_config_rules(ConfigRuleNames=[rule_name])["ConfigRules"]
    assert len(rules) == 1, f"expected exactly one ConfigRule named {rule_name!r}, got {len(rules)}: {rules!r}"
    assert rules[0]["Source"]["Owner"] == "CUSTOM_LAMBDA", (
        f"expected Source.Owner CUSTOM_LAMBDA for {rule_name!r}, got {rules[0]['Source'].get('Owner')!r}"
    )

    _start_rule_evaluation(config, rule_name)
    result = _poll_compliance(ctx, config, rule_name, account_id, "NON_COMPLIANT", timeout_s=_budget_s(ctx, 180.0))
    assert result["Annotation"] == "sim2real-cfn-deploy-check", (
        f"expected the annotation written by the deployed Lambda's PutEvaluations call "
        f"('sim2real-cfn-deploy-check'), got {result.get('Annotation')!r}"
    )


# ===== helpers =====

def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _safe(fn, *gone_codes, busy=()) -> None:
    """Run a teardown call: return on the resource's not-found codes, retry every 2 s the codes AWS
    answers while a dependency is still being released, and raise anything else."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 120
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy or time.monotonic() > deadline:
                raise
        time.sleep(2)


def _empty_and_delete_bucket(s3, bucket) -> None:
    """Config writes into its delivery bucket, so remove the objects before the bucket."""
    for obj in s3.list_objects_v2(Bucket=bucket).get("Contents", []):
        s3.delete_object(Bucket=bucket, Key=obj["Key"])
    s3.delete_bucket(Bucket=bucket)


def _retry(fn, attempts: int = 20, delay: float = 2.0, retry_codes: set[str] | None = None):
    from botocore.exceptions import ClientError

    last_exc: Exception | None = None
    for _ in range(attempts):
        try:
            return fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if retry_codes is None or code in retry_codes:
                last_exc = exc
                time.sleep(delay)
                continue
            raise
    assert last_exc is not None, "retry loop exhausted without ever capturing the failing exception"
    raise last_exc


def _ensure_configuration_recorder(ctx) -> None:
    config = ctx.client("config")
    if config.describe_configuration_recorders().get("ConfigurationRecorders", []):
        return

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-config-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "config.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "config-recorder-role"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole")
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"), "NoSuchEntity")
    )

    s3 = ctx.client("s3")
    bucket_name = ctx.unique_name("sim2real-config-bucket-").lower()
    region = ctx.region
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _safe(lambda: _empty_and_delete_bucket(s3, bucket_name), "NoSuchBucket", busy=("BucketNotEmpty",)))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real", "Value": "config-delivery-bucket"}]})

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bucket_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AWSConfigBucketPermissionsCheck",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:GetBucketAcl",
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Condition": {"StringEquals": {"AWS:SourceAccount": account_id}},
            },
            {
                "Sid": "AWSConfigBucketExistenceCheck",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:ListBucket",
                "Resource": f"arn:aws:s3:::{bucket_name}",
                "Condition": {"StringEquals": {"AWS:SourceAccount": account_id}},
            },
            {
                "Sid": "AWSConfigBucketDelivery",
                "Effect": "Allow",
                "Principal": {"Service": "config.amazonaws.com"},
                "Action": "s3:PutObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/AWSLogs/{account_id}/Config/*",
                "Condition": {"StringEquals": {"AWS:SourceAccount": account_id}},
            },
        ],
    }
    s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(bucket_policy))

    recorder_name = ctx.unique_name("sim2real-recorder-")
    config.put_configuration_recorder(
        ConfigurationRecorder={
            "name": recorder_name,
            "roleARN": role_arn,
            "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
        }
    )
    ctx.on_cleanup(lambda: _safe(lambda: config.delete_configuration_recorder(ConfigurationRecorderName=recorder_name), "NoSuchConfigurationRecorderException"))

    channel_name = ctx.unique_name("sim2real-channel-")
    _retry(
        lambda: config.put_delivery_channel(DeliveryChannel={"name": channel_name, "s3BucketName": bucket_name}),
        retry_codes={"InsufficientDeliveryPolicyException"},
    )
    ctx.on_cleanup(lambda: _safe(lambda: config.delete_delivery_channel(DeliveryChannelName=channel_name), "NoSuchDeliveryChannelException"))

    config.start_configuration_recorder(ConfigurationRecorderName=recorder_name)
    ctx.on_cleanup(lambda: _safe(lambda: config.stop_configuration_recorder(ConfigurationRecorderName=recorder_name), "NoSuchConfigurationRecorderException"))


def _deploy_stack(ctx, stack_name: str, template: dict[str, Any]) -> None:
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: cfn.delete_stack(StackName=stack_name)))
    cfn.get_waiter("stack_create_complete").wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300})


def _start_rule_evaluation(config, rule_name: str) -> None:
    from botocore.exceptions import ClientError

    for _ in range(30):
        try:
            config.start_config_rules_evaluation(ConfigRuleNames=[rule_name])
            return
        except ClientError as exc:
            # a busy rule is retried; any other refusal propagates as itself
            if exc.response["Error"]["Code"] != "ResourceInUseException":
                raise
        time.sleep(1)
    raise AssertionError("could not start config rule evaluation (rule stayed busy)")


def _poll_compliance(ctx, config, rule_name: str, account_id: str, expected: str, timeout_s: float = 180.0) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = config.get_compliance_details_by_config_rule(ConfigRuleName=rule_name)
        except Exception:
            resp = {"EvaluationResults": []}
        for result in resp.get("EvaluationResults", []):
            qualifier = result["EvaluationResultIdentifier"]["EvaluationResultQualifier"]
            if qualifier.get("ResourceId") == account_id:
                last = result["ComplianceType"]
                if last == expected:
                    return result
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"compliance for account {account_id} reaching {expected!r}: the run budget ended first; not graded")
    raise AssertionError(f"compliance for account {account_id} never reached {expected!r}, last seen {last!r}")


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
