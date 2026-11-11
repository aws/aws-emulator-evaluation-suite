"""cfn-deploy-iam-role-trust-s3-service-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-iam-role-trust-s3-service-positive"
GROUP = "iam-trust"
SERVICES = ["cloudformation", "dynamodb", "s3"]


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack-created IAM role trusting s3.amazonaws.com carries that principal in its live trust
    policy (GetRole) after deployment, and GetRole returns not-found after stack teardown."""
    role_name = _xname(ctx, "s3-trust-role")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Role": {
                    "Type": "AWS::IAM::Role",
                    "Properties": {
                        "RoleName": role_name,
                        "AssumeRolePolicyDocument": {
                            "Version": "2012-10-17",
                            "Statement": [
                                {
                                    "Effect": "Allow",
                                    "Principal": {"Service": "s3.amazonaws.com"},
                                    "Action": "sts:AssumeRole",
                                }
                            ],
                        },
                    },
                }
            },
            "Outputs": {"RoleName": {"Value": {"Ref": "Role"}}},
        }
    )
    result = _deploy_cfn(ctx, template)
    out_role = result["outputs"]["RoleName"]
    assert out_role == role_name, f"expected stack output RoleName {role_name!r}, got {out_role!r}"

    iam = ctx.client("iam")
    role = iam.get_role(RoleName=out_role)["Role"]
    trust_doc = role["AssumeRolePolicyDocument"]
    principal = trust_doc["Statement"][0]["Principal"]["Service"]
    assert principal == "s3.amazonaws.com", (
        f"expected live trust policy principal 's3.amazonaws.com', got {principal!r}"
    )
    assert trust_doc["Statement"][0]["Effect"] == "Allow", (
        f"expected live trust policy Effect 'Allow', got {trust_doc['Statement'][0]['Effect']!r}"
    )
    assert trust_doc["Statement"][0]["Action"] == "sts:AssumeRole", (
        f"expected live trust policy Action 'sts:AssumeRole', got {trust_doc['Statement'][0]['Action']!r}"
    )

    role_tags = {t["Key"]: t["Value"] for t in iam.list_role_tags(RoleName=out_role)["Tags"]}
    assert role_tags.get(_MANAGED_TAG_KEY) == "true", (
        f"expected stack-level tag {_MANAGED_TAG_KEY!r}='true' propagated onto the role, got {role_tags!r}"
    )

    # Prove teardown actually removes the role, not just the stack record: an operation
    # (GetRole) that demonstrably worked above must now fail with the specific not-found code.
    _delete_stack_and_wait(ctx, result["stack_name"])
    try:
        iam.get_role(RoleName=out_role)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "NoSuchEntity", f"expected NoSuchEntity after stack deletion, got {code!r}"
        message = exc.response["Error"].get("Message")
        assert message == f"The role with name {out_role} cannot be found.", (
            f"GetRole on the deleted role {out_role!r}: unexpected message {message!r}"
        )
    else:
        raise AssertionError(f"role {out_role!r} still exists after stack {result['stack_name']!r} deletion")


# ===== helpers =====
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
            if "does not exist" not in str(exc):
                raise
            return "GONE"

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=2.0,
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
