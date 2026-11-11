"""e2e-remediation-execution-resolves-noncompliant-resource."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags

CHECK = "e2e-remediation-execution-resolves-noncompliant-resource"
GROUP = "e2e"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "dp:api", "plane:data", "resource:account-singleton:config-delivery-channel", "resource:account-singleton:config-recorder")
def run(ctx) -> None:
    """A Lambda-backed rule marks the account NON_COMPLIANT via PutEvaluations; StartRemediationExecution
    runs an SSM automation that fixes the state, and a follow-up evaluation shows COMPLIANT."""
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    config = ctx.client("config")

    _ensure_configuration_recorder(ctx)

    param_name = ctx.unique_name("/sim2real-config/remediate-")
    ssm = ctx.client("ssm")
    ssm.put_parameter(
        Name=param_name, Value="false", Type="String", Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _safe(lambda: ssm.delete_parameter(Name=param_name), "ParameterNotFound"))

    lambda_role_arn = _create_lambda_role(ctx)
    function_arn, function_name = _create_evaluator_lambda(ctx, lambda_role_arn)
    _allow_config_to_invoke(ctx, function_name)

    automation_role_arn = _create_automation_role(ctx)
    doc_name = _create_remediation_document(ctx)

    rule_name = ctx.unique_name("sim2real-remediate-rule-")
    _put_lambda_config_rule(ctx, config, rule_name, function_arn, param_name)

    # Step 1: force an evaluation. The parameter starts "false" -> NON_COMPLIANT.
    _start_rule_evaluation(config, rule_name)
    before = _poll_compliance(config, rule_name, account_id, "NON_COMPLIANT", ctx=ctx, timeout_s=_budget_s(ctx, 180.0))
    assert before["Annotation"] == "sim2real-remediation-e2e", (
        f"expected the evaluator lambda's own annotation on the NON_COMPLIANT result, got {before['Annotation']!r}"
    )

    # Step 2: attach a remediation configuration and run it.
    config.put_remediation_configurations(RemediationConfigurations=[{
        "ConfigRuleName": rule_name,
        "TargetType": "SSM_DOCUMENT",
        "TargetId": doc_name,
        "Parameters": {
            "AutomationAssumeRole": {"StaticValue": {"Values": [automation_role_arn]}},
            "ParameterName": {"StaticValue": {"Values": [param_name]}},
        },
        "Automatic": False,
    }])
    ctx.on_cleanup(lambda: _safe(lambda: config.delete_remediation_configuration(ConfigRuleName=rule_name), "NoSuchRemediationConfigurationException", busy=("RemediationInProgressException",)))

    resource_key = {"resourceType": "AWS::::Account", "resourceId": account_id}
    start_resp = _retry(
        lambda: config.start_remediation_execution(ConfigRuleName=rule_name, ResourceKeys=[resource_key]),
        retry_codes={"InsufficientPermissionsException"},
    )
    assert start_resp.get("FailedItems", []) == [], (
        f"StartRemediationExecution reported failed items: {start_resp.get('FailedItems')}"
    )

    _poll_remediation_state(config, rule_name, resource_key, "SUCCEEDED", ctx=ctx, timeout_s=_budget_s(ctx, 240.0))

    # Step 3: the automation document flipped the parameter to "true"; re-evaluate.
    _start_rule_evaluation(config, rule_name)
    after = _poll_compliance(config, rule_name, account_id, "COMPLIANT", ctx=ctx, timeout_s=_budget_s(ctx, 180.0))
    assert after["Annotation"] == "sim2real-remediation-e2e", (
        f"expected the evaluator lambda's own annotation on the COMPLIANT result, got {after['Annotation']!r}"
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


def _retry(fn, attempts: int = 30, delay: float = 1.0, retry_codes: set[str] | None = None):
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
    assert last_exc is not None, "retry loop exited without success or a recorded exception"
    raise last_exc


def _ensure_configuration_recorder(ctx) -> None:
    """Reuse an existing configuration recorder, or create a minimal one if none
    exists yet -- PutConfigRule requires at least one to exist in the account."""
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
        # S3 rejects CreateBucketConfiguration.LocationConstraint for us-east-1, so omit it there.
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": region})
    ctx.on_cleanup(lambda: _safe(lambda: _empty_and_delete_bucket(s3, bucket_name), "NoSuchBucket", busy=("BucketNotEmpty",)))

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
    _retry(
        lambda: config.put_configuration_recorder(
            ConfigurationRecorder={
                "name": recorder_name,
                "roleARN": role_arn,
                "recordingGroup": {"allSupported": True, "includeGlobalResourceTypes": False},
            }
        ),
        retry_codes={"InvalidRoleException"},
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


def _create_lambda_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lambda-eval-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole")
    ctx.on_cleanup(
        lambda: _safe(
            lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"),
            "NoSuchEntity",
        )
    )
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["config:PutEvaluations"], "Resource": "*"},
            {"Effect": "Allow", "Action": ["ssm:GetParameter"], "Resource": "*"},
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-eval-inline", PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-eval-inline"), "NoSuchEntity"))
    return role_arn


def _create_evaluator_lambda(ctx, role_arn: str) -> tuple[str, str]:
    lam = ctx.client("lambda")
    function_name = ctx.unique_name("sim2real-config-eval-")
    code = (
        "import json\n"
        "import datetime\n"
        "import boto3\n\n\n"
        "def handler(event, context):\n"
        "    params = json.loads(event.get('ruleParameters') or '{}')\n"
        "    param_name = params.get('ParameterName')\n"
        "    ssm = boto3.client('ssm')\n"
        "    try:\n"
        "        value = ssm.get_parameter(Name=param_name)['Parameter']['Value']\n"
        "    except Exception:\n"
        "        value = 'false'\n"
        "    compliance = 'COMPLIANT' if value == 'true' else 'NON_COMPLIANT'\n"
        "    config = boto3.client('config')\n"
        "    config.put_evaluations(\n"
        "        Evaluations=[{\n"
        "            'ComplianceResourceType': 'AWS::::Account',\n"
        "            'ComplianceResourceId': event['accountId'],\n"
        "            'ComplianceType': compliance,\n"
        "            'Annotation': 'sim2real-remediation-e2e',\n"
        "            'OrderingTimestamp': datetime.datetime.utcnow(),\n"
        "        }],\n"
        "        ResultToken=event['resultToken'],\n"
        "    )\n"
        "    return 'done'\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)

    resp = _retry(
        lambda: lam.create_function(
            FunctionName=function_name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": buf.getvalue()},
            Timeout=30,
            Tags={"sim2real-check": CHECK},
        ),
        attempts=30,
        delay=1.0,
        retry_codes={"InvalidParameterValueException"},
    )
    ctx.on_cleanup(lambda: _safe(lambda: lam.delete_function(FunctionName=function_name), "ResourceNotFoundException"))
    lam.get_waiter("function_active_v2").wait(FunctionName=function_name, WaiterConfig={"Delay": 1, "MaxAttempts": 120})
    return resp["FunctionArn"], function_name


def _allow_config_to_invoke(ctx, function_name: str) -> None:
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=function_name,
        StatementId="sim2real-config-invoke",
        Action="lambda:InvokeFunction",
        Principal="config.amazonaws.com",
    )


def _create_automation_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-automation-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ssm.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": ["ssm:PutParameter"], "Resource": "*"}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="sim2real-automation-inline", PolicyDocument=json.dumps(inline_policy))
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-automation-inline"), "NoSuchEntity"))
    return role_arn


def _create_remediation_document(ctx) -> str:
    ssm = ctx.client("ssm")
    doc_name = ctx.unique_name("sim2real-remediate-doc-")
    content = {
        "schemaVersion": "0.3",
        "assumeRole": "{{ AutomationAssumeRole }}",
        "parameters": {
            "AutomationAssumeRole": {"type": "String"},
            "ParameterName": {"type": "String"},
        },
        "mainSteps": [
            {
                "name": "MarkResolved",
                "action": "aws:executeAwsApi",
                "inputs": {
                    "Service": "ssm",
                    "Api": "PutParameter",
                    "Name": "{{ ParameterName }}",
                    "Value": "true",
                    "Type": "String",
                    "Overwrite": True,
                },
            }
        ],
    }
    ssm.create_document(
        Name=doc_name,
        DocumentType="Automation",
        DocumentFormat="JSON",
        Content=json.dumps(content),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: ssm.delete_document(Name=doc_name), "InvalidDocument"))
    return doc_name


def _put_lambda_config_rule(ctx, config, rule_name: str, function_arn: str, param_name: str) -> None:
    def _put():
        config.put_config_rule(
            ConfigRule={
                "ConfigRuleName": rule_name,
                "Source": {
                    "Owner": "CUSTOM_LAMBDA",
                    "SourceIdentifier": function_arn,
                    "SourceDetails": [
                        {
                            "EventSource": "aws.config",
                            "MessageType": "ScheduledNotification",
                            "MaximumExecutionFrequency": "TwentyFour_Hours",
                        }
                    ],
                },
                "InputParameters": json.dumps({"ParameterName": param_name}),
            }
        )

    _retry(_put, attempts=30, delay=1.0, retry_codes={"InsufficientPermissionsException"})
    ctx.on_cleanup(lambda: _safe(lambda: config.delete_config_rule(ConfigRuleName=rule_name), "NoSuchConfigRuleException", busy=("ResourceInUseException",)))


def _start_rule_evaluation(config, rule_name: str) -> None:
    from botocore.exceptions import ClientError

    for _ in range(30):
        try:
            config.start_config_rules_evaluation(ConfigRuleNames=[rule_name])
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceInUseException":
                time.sleep(1)
                continue
            raise AssertionError(f"unexpected error starting rule evaluation: {code}") from exc
        return
    raise AssertionError("could not start config rule evaluation (rule stayed busy)")


def _poll_compliance(config, rule_name: str, account_id: str, expected: str, timeout_s: float = 180.0, *, ctx) -> dict[str, Any]:
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
        raise TimeoutError(f"compliance {expected!r} for account {account_id}: the run budget ended first; not graded")
    raise AssertionError(f"compliance for account {account_id} never reached {expected!r}, last seen {last!r}")


def _poll_remediation_state(config, rule_name: str, resource_key: dict[str, str], expected_state: str, timeout_s: float = 180.0, *, ctx) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = config.describe_remediation_execution_status(ConfigRuleName=rule_name, ResourceKeys=[resource_key])
        for status in resp.get("RemediationExecutionStatuses", []):
            key = status["ResourceKey"]
            if key.get("resourceId") == resource_key["resourceId"]:
                last = status["State"]
                if last == expected_state:
                    return status
                if last == "FAILED":
                    raise AssertionError(f"remediation execution failed: {status}")
        time.sleep(1)
    if _budget_spent(ctx):
        raise TimeoutError(f"remediation execution {expected_state!r}: the run budget ended first; not graded")
    raise AssertionError(f"remediation execution for {resource_key} never reached {expected_state!r}, last seen {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
