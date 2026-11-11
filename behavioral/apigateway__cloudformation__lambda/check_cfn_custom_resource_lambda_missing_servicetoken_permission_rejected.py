"""cfn-custom-resource-lambda-missing-servicetoken-permission-rejected."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-custom-resource-lambda-missing-servicetoken-permission-rejected"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cloudformation", "lambda"]


@tags("axis:negative-delivery", "cap:c3", "cap:c4", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "concern:negative-classes", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A stack service role without lambda:InvokeFunction cannot invoke a custom resource's ServiceToken:
    no Create event arrives and the stack rolls back, while the same template with a permitted role succeeds."""
    queue_url, _queue_arn = _create_queue(ctx)
    function_arn = _create_lambda_provider(ctx)
    role_denied_arn = _create_cfn_service_role(ctx, function_arn=function_arn, grant_invoke=False)
    role_allowed_arn = _create_cfn_service_role(ctx, function_arn=function_arn, grant_invoke=True)
    template = json.dumps(_stack_template())
    cfn = ctx.client("cloudformation")

    # --- negative: service role cannot invoke the Lambda ---
    denied_name = _xname(ctx, "stk-denied")
    _create_stack_retry_role(
        cfn,
        StackName=denied_name,
        TemplateBody=template,
        Parameters=[
            {"ParameterKey": "ServiceToken", "ParameterValue": function_arn},
            {"ParameterKey": "QueueUrl", "ParameterValue": queue_url},
        ],
        RoleARN=role_denied_arn,
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, denied_name))
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=denied_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "CREATE_COMPLETE"},
        timeout_s=300.0,
        interval_s=5.0,
        description=f"denied stack {denied_name}",
    )
    assert status == "ROLLBACK_COMPLETE"

    events = cfn.describe_stack_events(StackName=denied_name)["StackEvents"]
    cr_event = next(
        e
        for e in events
        if e["LogicalResourceId"] == "MyResource" and e["ResourceStatus"] == "CREATE_FAILED"
    )
    assert "lambda:InvokeFunction" in (cr_event.get("ResourceStatusReason") or "")

    _assert_no_message(ctx, queue_url, window_s=20.0)

    # --- positive control: same template, service role has the permission ---
    allowed_name = _xname(ctx, "stk-allowed")
    _create_stack_retry_role(
        cfn,
        StackName=allowed_name,
        TemplateBody=template,
        Parameters=[
            {"ParameterKey": "ServiceToken", "ParameterValue": function_arn},
            {"ParameterKey": "QueueUrl", "ParameterValue": queue_url},
        ],
        RoleARN=role_allowed_arn,
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, allowed_name))
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=allowed_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"},
        timeout_s=300.0,
        interval_s=5.0,
        description=f"allowed stack {allowed_name}",
    )
    assert status == "CREATE_COMPLETE"
    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=allowed_name)["Stacks"][0].get("Outputs", [])
    }
    assert outputs["RequestType"] == "Create"

    body = _receive_one_message(ctx, queue_url, timeout_s=60.0)
    assert body["RequestType"] == "Create"


def _stack_template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "ServiceToken": {"Type": "String"},
            "QueueUrl": {"Type": "String"},
        },
        "Resources": {
            "MyResource": {
                "Type": "Custom::Sim2RealTest",
                "Properties": {
                    "ServiceToken": {"Ref": "ServiceToken"},
                    "QueueUrl": {"Ref": "QueueUrl"},
                    "Value": "probe",
                },
            }
        },
        "Outputs": {"RequestType": {"Value": {"Fn::GetAtt": ["MyResource", "RequestType"]}}},
    }


def _standalone_provider_code() -> str:
    # This function is created directly via lambda.create_function (not through a CFN
    # template), so CloudFormation's automatic `cfnresponse` injection (which only applies to
    # AWS::Lambda::Function Code.ZipFile written inside a template) is unavailable — send the
    # custom-resource response over the documented raw HTTP PUT protocol instead.
    return "\n".join(
        [
            "import json",
            "import urllib.request",
            "import boto3",
            "",
            "def handler(event, context):",
            "    props = event.get('ResourceProperties') or {}",
            "    request_type = event['RequestType']",
            "    queue_url = props.get('QueueUrl')",
            "    if queue_url:",
            "        boto3.client('sqs').send_message(",
            "            QueueUrl=queue_url,",
            "            MessageBody=json.dumps({'RequestType': request_type}),",
            "        )",
            "    body = json.dumps({",
            "        'Status': 'SUCCESS',",
            "        'Reason': 'ok',",
            "        'PhysicalResourceId': 'sim2real-cr-fixed',",
            "        'StackId': event['StackId'],",
            "        'RequestId': event['RequestId'],",
            "        'LogicalResourceId': event['LogicalResourceId'],",
            "        'Data': {'RequestType': request_type},",
            "    }).encode()",
            "    req = urllib.request.Request(",
            "        url=event['ResponseURL'], data=body, method='PUT',",
            "        headers={'content-type': '', 'content-length': str(len(body))},",
            "    )",
            "    urllib.request.urlopen(req)",
        ]
    )


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _create_stack_retry_role(cfn, **kwargs):
    """create_stack with a just-created RoleARN can transiently fail with
    ValidationError("Role ... is invalid") while the new IAM role's trust policy propagates.
    Retry until CloudFormation accepts the role."""

    def _try():
        try:
            cfn.create_stack(**kwargs)
            return True
        except ClientError as e:
            if e.response["Error"]["Code"] == "ValidationError" and "is invalid" in str(e):
                return None
            raise

    _poll_until(
        _try,
        lambda r: r is not None,
        timeout_s=90.0,
        interval_s=3.0,
        description="create_stack accepting freshly-created RoleARN (IAM propagation)",
    )



def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _create_queue(ctx) -> tuple[str, str]:
    sqs = ctx.client("sqs")
    url = sqs.create_queue(QueueName=_xname(ctx, "q"))["QueueUrl"]
    ctx.on_cleanup(lambda: sqs.delete_queue(QueueUrl=url))
    arn = sqs.get_queue_attributes(QueueUrl=url, AttributeNames=["QueueArn"])["Attributes"][
        "QueueArn"
    ]
    return url, arn


def _receive_one_message(ctx, queue_url: str, *, timeout_s: float) -> dict[str, Any]:
    sqs = ctx.client("sqs")

    def _probe():
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        return resp.get("Messages", [])

    messages = _poll_until(
        _probe, lambda m: bool(m), timeout_s=timeout_s, interval_s=2.0,
        description="sqs side-channel message from custom resource lambda",
    )
    msg = messages[0]
    sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
    return json.loads(msg["Body"])


def _assert_no_message(ctx, queue_url: str, *, window_s: float) -> None:
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + window_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, WaitTimeSeconds=5)
        if resp.get("Messages"):
            raise AssertionError("side-channel message arrived despite missing invoke permission")


def _zip_from_code(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _try_create_function(lam, name: str, role_arn: str, zip_bytes: bytes):
    try:
        resp = lam.create_function(
            FunctionName=name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Timeout=30,
            Tags=_xsvc_resource_tags(),
        )
        return resp["FunctionArn"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "InvalidParameterValueException":
            return None  # role not yet assumable by lambda.amazonaws.com; retry
        raise


def _create_lambda_provider(ctx) -> str:
    iam = ctx.client("iam")
    lam = ctx.client("lambda")
    role_name = _xname(ctx, "provrole")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "lambda.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_xsvc_tags_kv()
    )["Role"]["Arn"]
    basic_policy = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
    # The handler sends a side-channel SQS message on every invocation — without this the
    # handler raises before ever calling cfnresponse.send(), and CloudFormation is left waiting
    # (silently, no CREATE_FAILED) for a response that will never arrive.
    sqs_policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "sqs:SendMessage", "Resource": "*"}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="AllowSqsSend", PolicyDocument=json.dumps(sqs_policy_doc)
    )

    func_name = _xname(ctx, "provfn")
    zip_bytes = _zip_from_code(_standalone_provider_code())
    ctx.on_cleanup(lambda _n=func_name: _delete_lambda_log_group(ctx, _n))
    func_arn = _poll_until(
        lambda: _try_create_function(lam, func_name, role_arn, zip_bytes),
        lambda r: r is not None,
        timeout_s=45.0,
        interval_s=3.0,
        description="lambda provider function creation (role propagation)",
    )

    def _cleanup():
        lam.delete_function(FunctionName=func_name)
        iam.delete_role_policy(RoleName=role_name, PolicyName="AllowSqsSend")
        iam.detach_role_policy(RoleName=role_name, PolicyArn=basic_policy)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return func_arn


def _create_cfn_service_role(ctx, *, function_arn: str, grant_invoke: bool) -> str:
    iam = ctx.client("iam")
    role_name = _xname(ctx, "cfnrole")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "cloudformation.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_xsvc_tags_kv()
    )["Role"]["Arn"]

    if grant_invoke:
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": function_arn}
            ],
        }
        iam.put_role_policy(
            RoleName=role_name, PolicyName="AllowInvoke", PolicyDocument=json.dumps(policy_doc)
        )

        def _cleanup():
            iam.delete_role_policy(RoleName=role_name, PolicyName="AllowInvoke")
            iam.delete_role(RoleName=role_name)

    else:

        def _cleanup():
            iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if not (
                (exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in exc.response["Error"].get("Message", ""))
            ):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
