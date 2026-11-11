"""cfn-custom-resource-signals-failure-stack-rollback-negative."""
from __future__ import annotations

import io
import json
import re
import time
import zipfile
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-custom-resource-signals-failure-stack-rollback-negative"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cloudformation", "lambda"]

_CUSTOM_RESOURCE_CODE = '''
import json
import urllib.request
import boto3

def handler(event, context):
    ssm = boto3.client("ssm")
    param_name = event["ResourceProperties"]["ParamName"]
    # Raises AccessDeniedException here (uncaught) if the execution role lacks
    # ssm:GetParameter -- the function exits without ever reaching the code below that
    # signals CloudFormation, so CloudFormation never receives a response.
    ssm.get_parameter(Name=param_name)
    response_body = {
        "Status": "SUCCESS",
        "Reason": "sim2real custom resource",
        "PhysicalResourceId": event.get("PhysicalResourceId") or context.log_stream_name,
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "Data": {},
    }
    data = json.dumps(response_body).encode("utf-8")
    req = urllib.request.Request(
        url=event["ResponseURL"], data=data, method="PUT", headers={"Content-Type": ""}
    )
    urllib.request.urlopen(req, timeout=10)
'''


# timing:real-time — workflow: 5 s https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-cloudformation-customresource.html
@tags("axis:negative-delivery", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "dp:endpoint", "plane:data", "timing:real-time")
def run(ctx) -> None:
    """A Lambda-backed custom resource missing an IAM permission never PUTs a response, and
    the rollback's own Delete signal gets no response either, so the stack lands in ROLLBACK_FAILED
    with a CREATE_FAILED reason naming the unanswered requestId."""
    ssm = ctx.client("ssm")
    param_name = ctx.unique_name("/sim2real/cfn-custom-resource/")
    ssm.put_parameter(Name=param_name, Value="ok", Type="String", Tags=_xsvc_tags_kv())
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=param_name))

    # ssm:GetParameter on the parameter is deliberately NOT granted to this role.
    denied_role = _create_lambda_role(ctx, policy_statements=None)
    denied_fn = _create_function(ctx, _CUSTOM_RESOURCE_CODE, denied_role, timeout=30)

    service_timeout = 5
    bad_stack = _create_stack(ctx, json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Signal": {
            "Type": "Custom::Sim2RealSignal",
            "Properties": {
                "ServiceToken": denied_fn["arn"],
                "ServiceTimeout": service_timeout,
                "ParamName": param_name,
            },
        }},
    }))

    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + 300
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=bad_stack["name"])["Stacks"][0]["StackStatus"]
        if last in ("ROLLBACK_COMPLETE", "ROLLBACK_FAILED"):
            break
        time.sleep(5.0)

    # effect absent: missing permission -> Lambda never signals CREATE success, and the
    # same missing permission blocks the implicit rollback Delete signal too -> the stack
    # can never roll the resource back either and lands in ROLLBACK_FAILED.
    assert last == "ROLLBACK_FAILED", f"got={last}"

    events = cfn.describe_stack_events(StackName=bad_stack["name"])["StackEvents"]
    cr_failed = next(
        (e for e in events
         if e["LogicalResourceId"] == "Signal" and e["ResourceStatus"] == "CREATE_FAILED"),
        None,
    )
    assert cr_failed is not None, (
        "the Signal resource has no CREATE_FAILED event; its statuses are "
        f"{[e['ResourceStatus'] for e in events if e['LogicalResourceId'] == 'Signal']!r}"
    )
    reason = cr_failed.get("ResourceStatusReason") or ""
    # the reason embeds the invocation's own AWS-generated RequestId between "[" and "]";
    # the literal text around it is pinned exactly, the id itself graded by form only.
    reason_prefix = (
        "CloudFormation did not receive a response from your Custom Resource. Please check "
        "your logs for requestId ["
    )
    reason_suffix = (
        "]. If you are using the Python cfn-response module, you may need to update your "
        "Lambda function code so that CloudFormation can attach the updated version."
    )
    assert reason.count("[") == 1 and reason.count("]") == 1, (
        f"the Signal resource's CREATE_FAILED reason is {reason!r}, "
        f"expected exactly one bracketed requestId"
    )
    bracket_open = reason.index("[")
    bracket_close = reason.index("]")
    literal_prefix = reason[: bracket_open + 1]
    request_id = reason[bracket_open + 1 : bracket_close]
    literal_suffix = reason[bracket_close:]
    assert literal_prefix == reason_prefix, (
        f"the Signal resource's CREATE_FAILED reason prefix is {literal_prefix!r}, expected {reason_prefix!r}"
    )
    assert re.fullmatch(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", request_id), (
        f"the Signal resource's CREATE_FAILED reason requestId is {request_id!r}, expected a UUID"
    )
    assert literal_suffix == reason_suffix, (
        f"the Signal resource's CREATE_FAILED reason suffix is {literal_suffix!r}, expected {reason_suffix!r}"
    )



# ===== self-contained helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _make_zip(code: str, filename: str = "index.py") -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, code)
    return buf.getvalue()


def _create_lambda_role(ctx, policy_statements=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-lam-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_xsvc_tags_kv()
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    logs_policy = ctx.unique_name("sim2real-lam-logs-")
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=logs_policy,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
            "Effect": "Allow",
            "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
            "Resource": "*",
        }]}),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=logs_policy))

    if policy_statements:
        pol_name = ctx.unique_name("sim2real-lam-pol-")
        iam.put_role_policy(
            RoleName=role_name,
            PolicyName=pol_name,
            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": policy_statements}),
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=pol_name))
    return role_arn


def _create_function(ctx, code: str, role_arn: str, timeout: int = 15) -> dict[str, str]:
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-fn-")
    zip_bytes = _make_zip(code)

    def _try_create():
        try:
            return lam.create_function(
                FunctionName=name,
                Runtime="python3.12",
                Role=role_arn,
                Handler="index.handler",
                Code={"ZipFile": zip_bytes},
                Timeout=timeout,
                Tags=_xsvc_resource_tags(),
            )
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValueException":
                return None
            raise

    resp = _poll_until(
        _try_create,
        lambda r: r is not None,
        timeout_s=60,
        interval_s=3.0,
        description=f"lambda {name} creatable (IAM role propagation)",
    )
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    ctx.on_cleanup(lambda: _reap_log_group(ctx, f"/aws/lambda/{name}"))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"lambda {name} Active",
    )
    return {"name": name, "arn": resp["FunctionArn"]}


def _reap_log_group(ctx, name: str) -> None:
    """Delete the log group Lambda creates for the function; only its absence is tolerated."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _create_stack(ctx, template_body: str, tags=None) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-stack-")
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": tags or _xsvc_tags_kv(),
    }
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    # The Signal resource's ServiceToken function can never answer its Delete either, so a
    # DELETE_FAILED stack is deleted again retaining it (a record backed by no AWS resource).
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id, retain=("Signal",)))
    return {"name": name, "id": stack_id}


def _teardown_stack(cfn, stack_id: str, *, retain: tuple[str, ...] = (), timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; a DELETE_FAILED stack is deleted
    again retaining ``retain``, and a second DELETE_FAILED or a timeout raises."""
    for attempt in range(2):
        prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if prior == "DELETE_COMPLETE":
            return
        if prior == "DELETE_FAILED" and retain:
            cfn.delete_stack(StackName=stack_id, RetainResources=list(retain))
        else:
            cfn.delete_stack(StackName=stack_id)
        deadline = time.monotonic() + timeout_s
        moved = False
        while True:
            stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
            status = stack["StackStatus"]
            moved = moved or status != prior
            if status == "DELETE_COMPLETE":
                return
            if status == "DELETE_FAILED" and moved:
                if attempt == 0 and retain:
                    break
                raise AssertionError(
                    f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}"
                )
            if time.monotonic() > deadline:
                raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
            time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
