"""cfn-lambda-role-missing-trust-principal-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "cfn-lambda-role-missing-trust-principal-rejected"
GROUP = "permission-boundary"
SERVICES = ["apigateway", "cloudformation", "lambda"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack whose function role does not trust lambda.amazonaws.com fails function creation and rolls
    back leaving no function, while the same template with the correct trust principal yields an invocable function."""
    cfn = ctx.client("cloudformation")
    lam = ctx.client("lambda")

    # --- negative: role trusts only ec2.amazonaws.com, not lambda.amazonaws.com ---
    bad_name = _xname(ctx, "stk-badtrust")
    bad_function_name = ctx.unique_name("sim2real-xsvc-badtrust-fn-")
    cfn.create_stack(
        StackName=bad_name,
        TemplateBody=json.dumps(
            _template(trusted_service="ec2.amazonaws.com", function_name=bad_function_name)
        ),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
        Tags=_xsvc_tags_kv(),
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, bad_name))
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=bad_name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "CREATE_COMPLETE"},
        timeout_s=180.0,
        interval_s=5.0,
        description=f"bad-trust stack {bad_name}",
    )
    assert status == "ROLLBACK_COMPLETE", (
        f"expected the bad-trust stack {bad_name} to roll back, got status={status!r}"
    )

    # CloudFormation's rollback phase emits a DELETE_SKIPPED event for resources that were
    # never actually created (like this one), and that event is newer than the CREATE_FAILED
    # event — so pick the CREATE_FAILED event explicitly rather than the newest event for this
    # logical id.
    events = cfn.describe_stack_events(StackName=bad_name)["StackEvents"]
    fn_event = next(
        e
        for e in events
        if e["LogicalResourceId"] == "EchoFunction" and e["ResourceStatus"] == "CREATE_FAILED"
    )
    reason = fn_event.get("ResourceStatusReason") or ""
    assert "cannot be assumed" in reason, (
        f"expected the CREATE_FAILED reason for EchoFunction to name the trust-policy "
        f"rejection, got reason={reason!r}"
    )

    # Effect absent: the function name is fixed in the template (not left to CloudFormation to
    # generate), so this is an independent read against a known name rather than a lookup keyed
    # off whatever placeholder PhysicalResourceId the failed attempt may or may not have
    # recorded — Lambda's CreateFunction call is atomic, so a name that was never created reads
    # back as ResourceNotFoundException regardless.
    lam_error, lam_message = _error(lambda: lam.get_function(FunctionName=bad_function_name))
    assert lam_error == "ResourceNotFoundException", (
        f"expected function {bad_function_name} to never have come into existence after the "
        f"trust-policy rejection, got error={lam_error!r}"
    )
    expected_message = (
        f"Function not found: arn:aws:lambda:{ctx.region}:{ctx.account}:function:{bad_function_name}"
    )
    assert lam_message == expected_message, (
        f"expected message {expected_message!r}, got {lam_message!r}"
    )

    # --- positive control: correct trust principal, same shape of template ---
    good_function_name = ctx.unique_name("sim2real-xsvc-goodtrust-fn-")
    good = _deploy_cfn(
        ctx, json.dumps(_template(trusted_service="lambda.amazonaws.com", function_name=good_function_name))
    )
    resp = lam.invoke(FunctionName=good["outputs"]["FunctionArn"], Payload=b"{}")
    assert resp["StatusCode"] == 200, f"expected a successful invoke, got StatusCode={resp['StatusCode']}"
    assert "FunctionError" not in resp, f"expected no FunctionError, got {resp.get('FunctionError')!r}"
    payload = json.loads(resp["Payload"].read())
    assert payload == {"ok": True}, f"expected the handler's real return value, got {payload!r}"


def _template(*, trusted_service: str, function_name: str) -> dict[str, Any]:
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
                                "Principal": {"Service": trusted_service},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
                    ],
                },
            },
            "EchoFunction": {
                "Type": "AWS::Lambda::Function",
                "Properties": {
                    "FunctionName": function_name,
                    "Handler": "index.handler",
                    "Runtime": "python3.12",
                    "Timeout": 30,
                    "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                    "Code": {
                        "ZipFile": {
                            "Fn::Join": [
                                "\n",
                                [
                                    "def handler(event, context):",
                                    "    return {'ok': True}",
                                ],
                            ]
                        }
                    },
                },
            },
        },
        "Outputs": {"FunctionArn": {"Value": {"Fn::GetAtt": ["EchoFunction", "Arn"]}}},
    }


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _error(fn) -> tuple[str, str]:
    """Run ``fn`` and return the (code, message) of the ClientError it raises; a call that
    succeeds fails the check."""
    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


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


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
        ),
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
