"""deploy-transfer-service-managed-user-exists-after-create-and-gone-after-stack-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-transfer-service-managed-user-exists-after-create-and-gone-after-stack-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "transfer"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 300.0


def wait_stack(cf, stack_id, terminal=_TERMINAL, timeout_s=300.0):
    """Poll DescribeStacks by StackId every 2 s until a status in ``terminal``; return it.

    Every error propagates: no ClientError ever stands for "done" or "gone".
    """
    deadline = time.monotonic() + timeout_s
    while True:
        status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if status in terminal:
            return status
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status!r} after {timeout_s:.0f}s")
        time.sleep(2)


def delete_stack(cf, stack_id):
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice."""
    deadline = time.monotonic() + _DELETE_BUDGET_S
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    if status.endswith("_IN_PROGRESS") and status not in ("DELETE_IN_PROGRESS",
                                                          "REVIEW_IN_PROGRESS"):
        wait_stack(cf, stack_id, _TERMINAL, deadline - time.monotonic())
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"},
                        deadline - time.monotonic())
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}")


def delete_stack_named(cf, name, stack_id=None):
    """delete_stack by ``stack_id``, else by the StackId DescribeStacks(StackName=name) returns.

    A ``name`` CloudFormation never accepted ("does not exist") is nothing to delete; the
    client's own ``ClientError`` keeps the helper free of imports.
    """
    if stack_id is None:
        try:
            stack_id = cf.describe_stacks(StackName=name)["Stacks"][0]["StackId"]
        except cf.exceptions.ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) == (
                    "ValidationError", f"Stack with id {name} does not exist"):
                return
            raise
    delete_stack(cf, stack_id)


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name>; cleanup registered before the call."""
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def stack_outputs(cf, stack_id):
    """The stack's Outputs as {OutputKey: OutputValue}."""
    stack = cf.describe_stacks(StackName=stack_id)["Stacks"][0]
    return {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


# ---- Check-specific: the template, then run(). ----

_TRUST_TRANSFER = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "transfer.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}


def _template(server_id: str, role_arn: str, username: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "User": {
                "Type": "AWS::Transfer::User",
                "Properties": {
                    "ServerId": server_id,
                    "UserName": username,
                    "Role": role_arn,
                    "HomeDirectory": "/",
                    "HomeDirectoryType": "PATH",
                },
            },
        },
        "Outputs": {
            "UserArn": {"Value": {"Fn::GetAtt": ["User", "Arn"]}},
        },
    })


def _error(fn):
    """``(Error.Code, Error.Message)`` ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Transfer::User on a SERVICE_MANAGED server exists after
    CREATE_COMPLETE with its declared Role and an Arn matching GetAtt Arn, and DescribeUser
    refuses it with ResourceNotFoundException once the stack that created it is deleted.
    """
    iam = ctx.client("iam")
    transfer = ctx.client("transfer")
    cfn = ctx.client("cloudformation")

    role_name = ctx.unique_name("sim2real-transfer-role-")
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(_TRUST_TRANSFER),
    )["Role"]["Arn"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))

    server_id = transfer.create_server()["ServerId"]
    ctx.on_cleanup(_teardown(lambda: transfer.delete_server(ServerId=server_id),
                              "ResourceNotFoundException"))

    username = ctx.unique_name("sim2real_user_")
    stack_name = ctx.unique_name("sim2real-cfntruser-")
    stack_id = create_stack(ctx, cfn, stack_name, _template(server_id, role_arn, username))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack ended {status!r}"

    outputs = stack_outputs(cfn, stack_id)
    user = transfer.describe_user(ServerId=server_id, UserName=username)["User"]
    got = (user["Role"], user["Arn"])
    want = (role_arn, outputs["UserArn"])
    assert got == want, f"describe_user returned {got!r}, expected {want!r}"

    delete_stack(cfn, stack_id)
    code, message = _error(
        lambda: transfer.describe_user(ServerId=server_id, UserName=username)
    )
    assert (code, message) == ("ResourceNotFoundException", "Unknown user"), (
        f"describe_user after stack delete raised ({code!r}, {message!r}), "
        f"expected ('ResourceNotFoundException', 'Unknown user')"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
