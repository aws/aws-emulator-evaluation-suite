"""deploy-cfn-lambda-role-wrong-trust-rejected."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-lambda-role-wrong-trust-rejected"
GROUP = "iam-trust"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:control", "plane:data")
def run(ctx) -> None:
    """A stack whose Lambda role trusts only ec2.amazonaws.com rolls back to ROLLBACK_COMPLETE with a
    "cannot be assumed" reason and leaves no function, while the same stack trusting
    lambda.amazonaws.com deploys and invokes."""
    ctx.verify_account_safety()
    bad_stack_name = _xname(ctx, "stk-badtrust")
    cfn = ctx.client("cloudformation")
    cfn.create_stack(
        StackName=bad_stack_name,
        TemplateBody=json.dumps(_template(trust_principal="ec2.amazonaws.com")),
        Tags=_xsvc_tags_kv(),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, bad_stack_name))

    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=bad_stack_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "CREATE_FAILED"},
        timeout_s=180,
        interval_s=5.0,
        description=f"CFN stack {bad_stack_name} reaching a terminal status",
    )
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    # Pin the rollback to the trust-policy rejection specifically, not just any stack failure.
    # Rollback emits a DELETE_SKIPPED event for TrustFn (never actually created) that is newer
    # than its CREATE_FAILED event, so pick CREATE_FAILED explicitly rather than the newest event
    # for this logical id.
    events = cfn.describe_stack_events(StackName=bad_stack_name)["StackEvents"]
    fn_event = next(
        e
        for e in events
        if e["LogicalResourceId"] == "TrustFn" and e["ResourceStatus"] == "CREATE_FAILED"
    )
    reason = fn_event.get("ResourceStatusReason") or ""
    # message varies: CloudFormation wraps the handler message with a per-call Request ID and
    # RequestToken, so only the Lambda refusal text inside it is stable.
    assert "cannot be assumed" in reason, f"expected a role-assumption failure reason, got {reason!r}"

    # Effect absent: the function this stack tried to create was never left behind.
    lam = ctx.client("lambda")
    bad_fn_name = f"{bad_stack_name}-fn"
    code, message = _error_code(lambda: lam.get_function(FunctionName=bad_fn_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}: {message!r}"
    bad_fn_arn = f"arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_fn_name}"
    assert message == f"Function not found: {bad_fn_arn}", f"unexpected GetFunction not-found message: {message!r}"

    # Positive control: identical stack, only the trust principal is fixed.
    good_stack = _deploy_cfn(ctx, json.dumps(_template(trust_principal="lambda.amazonaws.com")), timeout_s=180)
    outputs = good_stack["outputs"]
    resp = lam.invoke(FunctionName=outputs["FunctionName"], Payload=b"{}")
    assert "FunctionError" not in resp, resp
    body = json.loads(resp["Payload"].read())
    assert body["ok"] is True, f"expected the correctly-trusted role's function to return ok=True, got {body!r}"


def _error_code(fn):
    """Call fn() and return its (code, message); a call that succeeds raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _template(*, trust_principal: str) -> dict[str, Any]:
    lambda_code = "def handler(event, context):\n    return {'ok': True}\n"
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": trust_principal},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
            },
            "TrustFn": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": {"Fn::Sub": "${AWS::StackName}-fn"},
                    "Runtime": "python3.12",
                    "Handler": "index.handler",
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Timeout": 15,
                    "Code": {"ZipFile": lambda_code},
                },
            },
        },
        "Outputs": {
            "FunctionName": {"Value": {"Ref": "TrustFn"}},
        },
    }


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


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


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


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
