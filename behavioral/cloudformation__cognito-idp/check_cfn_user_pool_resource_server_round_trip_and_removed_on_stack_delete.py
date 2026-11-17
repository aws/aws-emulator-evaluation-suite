"""cfn-user-pool-resource-server-round-trip-and-removed-on-stack-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-user-pool-resource-server-round-trip-and-removed-on-stack-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "cognito-idp"]

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED",
})


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
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, timeout_s=300.0)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}")


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name> (propagates to every taggable resource); cleanup first.

    ``name`` comes from ctx.unique_name("sim2real-..."), so the tag value is unique per run. The
    cleanup is registered before the call: a stack AWS accepted is deleted even if the call raises.
    """
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


def expect_error(fn, code, message, undo=None):
    """Assert ``fn()`` raises exactly ``(code, message)``.

    On an unexpected success ``undo(result)`` registers the cleanup before the failure is raised.
    """
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    if undo is not None:
        undo(result)
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _template(*, pool_id: str, identifier: str, name: str, scopes: list[dict]) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ResourceServer": {
                "Type": "AWS::Cognito::UserPoolResourceServer",
                "Properties": {
                    "UserPoolId": pool_id,
                    "Identifier": identifier,
                    "Name": name,
                    "Scopes": scopes,
                },
            },
        },
        "Outputs": {
            "ResourceServerRef": {"Value": {"Ref": "ResourceServer"}},
        },
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::Cognito::UserPoolResourceServer on an existing pool reaches
    CREATE_COMPLETE with its Ref equal to the declared Identifier and DescribeResourceServer
    returning the declared Name and Scopes; deleting the stack removes only the resource server."""
    cfn, cognito = ctx.client("cloudformation"), ctx.client("cognito-idp")
    pool_name = ctx.unique_name("sim2real-behav-cogrspool-")
    identifier = f"https://{ctx.unique_name('sim2real-behav-cogrsid-')}.example.com"
    server_name = ctx.unique_name("sim2real-behav-cogrsname-")
    declared_scopes = [
        {"ScopeName": "read", "ScopeDescription": "read scope"},
        {"ScopeName": "write", "ScopeDescription": "write scope"},
    ]

    pool_id = cognito.create_user_pool(
        PoolName=pool_name, UserPoolTags={"sim2real": CHECK}
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    stack_id = create_stack(
        ctx, cfn, ctx.unique_name("sim2real-behav-cogrsstack-"),
        _template(pool_id=pool_id, identifier=identifier, name=server_name,
                  scopes=declared_scopes),
    )
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", f"stack ended {status!r}"

    out = stack_outputs(cfn, stack_id)
    assert out["ResourceServerRef"] == identifier, (
        f"expected Ref to equal the declared Identifier {identifier!r}, got {out['ResourceServerRef']!r}"
    )

    server = cognito.describe_resource_server(
        UserPoolId=pool_id, Identifier=identifier
    )["ResourceServer"]
    assert server["Identifier"] == identifier, (
        f"expected Identifier {identifier!r}, got {server['Identifier']!r}"
    )
    assert server["Name"] == server_name, (
        f"expected Name {server_name!r}, got {server['Name']!r}"
    )
    got_scopes = sorted(server["Scopes"], key=lambda s: s["ScopeName"])
    want_scopes = sorted(declared_scopes, key=lambda s: s["ScopeName"])
    assert got_scopes == want_scopes, f"expected Scopes {want_scopes!r}, got {got_scopes!r}"

    cfn.delete_stack(StackName=stack_id)
    status = wait_stack(cfn, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"})
    assert status == "DELETE_COMPLETE", f"stack delete ended {status!r}"

    resource_server_gone = (
        "ResourceNotFoundException",
        f"{identifier} does not exist in user pool {pool_id}.",
    )
    expect_error(
        lambda: cognito.describe_resource_server(UserPoolId=pool_id, Identifier=identifier),
        *resource_server_gone,
    )

    pool_after = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    assert pool_after["Id"] == pool_id, (
        f"expected the pool to remain after the stack's resource server was removed, "
        f"got {pool_after.get('Id')!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
