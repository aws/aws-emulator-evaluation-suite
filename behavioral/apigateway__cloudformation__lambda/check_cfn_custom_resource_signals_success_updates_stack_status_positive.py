"""cfn-custom-resource-signals-success-updates-stack-status-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-custom-resource-signals-success-updates-stack-status-positive"
GROUP = "event-propagation"
SERVICES = ["apigateway", "cloudformation", "lambda"]

TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}
TAGS_KV = [{"Key": k, "Value": v} for k, v in TAGS.items()]

_TERMINAL_FAILURE_STATUSES = {
    "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "DELETE_FAILED",
}

_CUSTOM_RESOURCE_CODE = '''
import json
import urllib.request

def handler(event, context):
    response_body = {
        "Status": "SUCCESS",
        "Reason": "sim2real custom resource always succeeds",
        "PhysicalResourceId": event.get("PhysicalResourceId") or context.log_stream_name,
        "StackId": event["StackId"],
        "RequestId": event["RequestId"],
        "LogicalResourceId": event["LogicalResourceId"],
        "Data": {"Marker": "sim2real-ok"},
    }
    data = json.dumps(response_body).encode("utf-8")
    req = urllib.request.Request(
        url=event["ResponseURL"], data=data, method="PUT", headers={"Content-Type": ""}
    )
    urllib.request.urlopen(req, timeout=10)
'''


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "dp:api", "dp:endpoint", "plane:data")
def run(ctx) -> None:
    """A Lambda-backed custom resource that PUTs a SUCCESS response to CloudFormation's
    presigned callback URL is observed as the stack transitioning to CREATE_COMPLETE, and
    the custom resource's returned Data payload round-trips through a stack Output."""
    role_arn = _create_lambda_role(ctx)
    fn = _create_function(ctx, _CUSTOM_RESOURCE_CODE, role_arn)

    template = json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Signal": {
                "Type": "Custom::Sim2RealSignal",
                "Properties": {"ServiceToken": fn["arn"], "ServiceTimeout": 60},
            },
        },
        "Outputs": {"MarkerOutput": {"Value": {"Fn::GetAtt": ["Signal", "Marker"]}}},
    })
    stack = _create_stack(ctx, template, tags=TAGS_KV)
    status = _wait_stack_status(ctx, stack["name"], "CREATE_COMPLETE", timeout_s=120)
    assert status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, stack {stack['name']} reached {status!r}"

    cfn = ctx.client("cloudformation")
    outputs = cfn.describe_stacks(StackName=stack["name"])["Stacks"][0].get("Outputs", [])
    marker_matches = [o["OutputValue"] for o in outputs if o["OutputKey"] == "MarkerOutput"]
    assert marker_matches, f"expected a MarkerOutput stack output, got outputs {outputs!r}"
    marker = marker_matches[0]
    assert marker == "sim2real-ok", f"expected MarkerOutput 'sim2real-ok' (round-tripped from the custom resource's Data), got {marker!r}"


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
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=TAGS_KV
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    managed_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_arn))

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
                Tags=dict(TAGS),
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
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=2.0,
        description=f"lambda {name} Active",
    )
    return {"name": name, "arn": resp["FunctionArn"]}


def _create_stack(ctx, template_body: str, tags=None) -> dict[str, str]:
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-stack-")
    kwargs: dict[str, Any] = {"StackName": name, "TemplateBody": template_body}
    if tags:
        kwargs["Tags"] = tags
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=name))
    return {"name": name, "id": stack_id}


def _wait_stack_status(ctx, stack_name: str, expected_status: str, timeout_s: float = 180.0) -> str:
    cfn = ctx.client("cloudformation")

    def _probe():
        status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if status in _TERMINAL_FAILURE_STATUSES:
            raise AssertionError(
                f"stack {stack_name} reached terminal failure status {status!r} while waiting for {expected_status!r}"
            )
        return status

    return _poll_until(
        _probe,
        lambda s: s == expected_status,
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"stack {stack_name} reaches {expected_status}",
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
