"""cfn-iam-role-permissions-boundary-in-template-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-iam-role-permissions-boundary-in-template-positive"
GROUP = "permission-boundary"
SERVICES = ["cloudformation", "iam", "lambda", "s3"]

_BOUNDARY_ARN = "arn:aws:iam::aws:policy/PowerUserAccess"


@tags("axis:happy-path", "cap:c3", "cap:c7", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A template PermissionsBoundary on an IAM role is applied and caps it: the function's s3 call
    succeeds, its iam:CreateUser (allowed by the identity policy) is AccessDenied and creates no user,
    and after the boundary is detached the identical call succeeds."""
    function_name = _xname(ctx, "fn")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "ExecRole": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "PermissionsBoundary": _BOUNDARY_ARN,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "lambda.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                        "Policies": [
                            {
                                "PolicyName": "wide-identity-policy",
                                "PolicyDocument": {
                                    "Version": "2012-10-17",
                                    "Statement": [
                                        {
                                            "Effect": "Allow",
                                            "Action": ["s3:ListAllMyBuckets", "iam:CreateUser"],
                                            "Resource": "*",
                                        }
                                    ],
                                },
                            }
                        ],
                    },
                },
                "Function": {
                    "Type": "AWS::Lambda::Function",
                    "Properties": {
                        "FunctionName": function_name,
                        "Handler": "index.handler",
                        "Runtime": "python3.12",
                        "Timeout": 10,
                        "Role": {"Fn::GetAtt": ["ExecRole", "Arn"]},
                        "Code": {
                            "ZipFile": (
                                "import boto3\n"
                                "def handler(event, context):\n"
                                "    action = event['action']\n"
                                "    try:\n"
                                "        if action == 'list_buckets':\n"
                                "            boto3.client('s3').list_buckets()\n"
                                "        elif action == 'create_user':\n"
                                "            boto3.client('iam').create_user(UserName=event['username'])\n"
                                "        return {'ok': True}\n"
                                "    except Exception as exc:\n"
                                "        return {'ok': False, 'error': str(exc)}\n"
                            )
                        },
                    },
                },
            },
            "Outputs": {"RoleArn": {"Value": {"Fn::GetAtt": ["ExecRole", "Arn"]}}},
        }
    )

    result = _deploy_cfn(ctx, template, capabilities=["CAPABILITY_IAM"])
    role_name = result["outputs"]["RoleArn"].split("/")[-1]

    iam = ctx.client("iam")
    role = iam.get_role(RoleName=role_name)["Role"]
    assert role["PermissionsBoundary"]["PermissionsBoundaryArn"] == _BOUNDARY_ARN, (
        f"CFN must translate the template's PermissionsBoundary into the deployed role's own "
        f"attribute; GetRole reports {role.get('PermissionsBoundary')!r}, expected "
        f"PermissionsBoundaryArn {_BOUNDARY_ARN!r}"
    )

    _wait_lambda_active(ctx, function_name)

    # within the boundary (s3 is not excluded by PowerUserAccess) + identity policy allows it
    _, allowed = _invoke_lambda(ctx, function_name, {"action": "list_buckets"})
    assert allowed == {"ok": True}, (
        f"s3:ListAllMyBuckets is inside both the boundary and the identity policy, so the real "
        f"invoke must succeed; got {allowed!r}"
    )

    # outside the boundary (PowerUserAccess excludes iam:CreateUser) despite the identity policy
    # explicitly allowing it -- the boundary is an enforced ceiling, not just a recorded field
    denied_username = _xname(ctx, "boundtest-denied")
    _, denied = _invoke_lambda(
        ctx, function_name, {"action": "create_user", "username": denied_username}
    )
    assert denied["ok"] is False, (
        f"iam:CreateUser is outside PowerUserAccess, so the boundary must refuse it even though "
        f"the identity policy explicitly allows it; got {denied!r}"
    )
    assert "AccessDenied" in denied["error"], (
        f"the refusal must be the specific AccessDenied the boundary produces; got "
        f"{denied['error']!r}"
    )

    # effect absent: the boundary-denied CreateUser must leave no user behind
    absent_code, absent_message = _error_code(lambda: iam.get_user(UserName=denied_username))
    assert absent_code == "NoSuchEntity", (
        f"the boundary-denied CreateUser must never have created {denied_username!r}; GetUser "
        f"returned {absent_code!r} instead of NoSuchEntity"
    )
    expected_absent = f"The user with name {denied_username} cannot be found."
    assert absent_message == expected_absent, (
        f"GetUser message {absent_message!r} != {expected_absent!r}"
    )

    # restore: detach the boundary directly (CFN owns only the deploy-time value, not a live
    # update path for it) and prove the IDENTICAL call succeeds -- so the boundary, and only
    # the boundary, was the cause of the earlier refusal rather than some other break in the deploy
    iam.delete_role_permissions_boundary(RoleName=role_name)
    after = iam.get_role(RoleName=role_name)["Role"]
    assert "PermissionsBoundary" not in after, (
        f"DeleteRolePermissionsBoundary must remove the field from GetRole; still reports "
        f"{after.get('PermissionsBoundary')!r}"
    )

    restored_username = _xname(ctx, "boundtest-restored")
    ctx.on_cleanup(lambda: _delete_user_if_present(iam, restored_username))
    _, restored = _poll_invoke(
        ctx,
        function_name,
        {"action": "create_user", "username": restored_username},
        lambda body: body.get("ok") is True,
        timeout_s=120.0,
        interval_s=5.0,
        description="iam:CreateUser succeeds once the boundary is detached",
    )
    assert restored == {"ok": True}, (
        f"with the boundary detached and nothing else changed, the identical CreateUser call the "
        f"identity policy already allowed must now succeed; got {restored!r}"
    )


_XSVC_PREFIX = "sim2real-xsvc-"

_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    """A unique, prefix-tagged resource name: sim2real-xsvc-<kind>-<uuid>."""
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    """Delete a CFN stack and wait for DELETE_COMPLETE (teardown; errors swallowed by on_cleanup)."""
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
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
) -> dict[str, Any]:
    """Deploy a CloudFormation stack (template body str or Path); wait for CREATE_COMPLETE;
    register delete-stack-and-wait teardown. Returns {stack_name,stack_id,outputs:{k:v}}."""
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
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
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


def _wait_lambda_active(ctx, function_name: str, timeout_s: float = 90.0) -> None:
    lam = ctx.client("lambda")
    _poll_until(
        lambda: lam.get_function_configuration(FunctionName=function_name)["State"],
        lambda s: s == "Active",
        timeout_s=timeout_s,
        interval_s=3.0,
        description=f"lambda {function_name} Active",
    )


def _invoke_lambda(ctx, function_name: str, payload: dict | None = None):
    lam = ctx.client("lambda")
    resp = lam.invoke(
        FunctionName=function_name,
        Payload=json.dumps(payload or {}).encode("utf-8"),
    )
    assert "FunctionError" not in resp, resp.get("FunctionError")
    body = json.loads(resp["Payload"].read())
    return resp, body


def _poll_invoke(
    ctx, function_name: str, payload: dict, predicate, *, timeout_s: float, interval_s: float, description: str
):
    """Poll _invoke_lambda(...) until predicate(body) is truthy; raises on timeout (IAM boundary
    changes are evaluated per-call but propagate across replicas, so a single shot can be racy)."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp, last = _invoke_lambda(ctx, function_name, payload)
        if predicate(last):
            return resp, last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last body: {last!r}")


def _error_code(fn) -> tuple[str, str]:
    """``(code, message)`` of the ClientError ``fn`` raises; an unexpected success fails."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to be refused, but it succeeded")


def _delete_user_if_present(iam, username: str) -> None:
    try:
        iam.delete_user(UserName=username)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
