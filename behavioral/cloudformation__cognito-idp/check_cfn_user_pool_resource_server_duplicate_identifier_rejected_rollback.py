"""cfn-user-pool-resource-server-duplicate-identifier-rejected-rollback."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-user-pool-resource-server-duplicate-identifier-rejected-rollback"
GROUP = "overly-permissive"
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


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page."""
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


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
    status = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if status == "DELETE_COMPLETE":
        return
    cf.delete_stack(StackName=stack_id)
    status = wait_stack(cf, stack_id, {"DELETE_COMPLETE", "DELETE_FAILED"}, timeout_s=300.0)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id} delete ended {status!r}")


def create_stack(ctx, cf, name, template, **kw):
    """CreateStack tagged sim2real=<name>; cleanup registered before the call so a stack AWS
    accepted (even one that then rolls back) is deleted even if the call itself raises."""
    created = {}
    ctx.on_cleanup(lambda: delete_stack_named(cf, name, created.get("StackId")))
    created["StackId"] = cf.create_stack(
        StackName=name, TemplateBody=template, Tags=[{"Key": "sim2real", "Value": name}], **kw
    )["StackId"]
    return created["StackId"]


def _template(*, pool_id: str, identifier: str, name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ResourceServer": {
                "Type": "AWS::Cognito::UserPoolResourceServer",
                "Properties": {
                    "UserPoolId": pool_id,
                    "Identifier": identifier,
                    "Name": name,
                    "Scopes": [{"ScopeName": "read", "ScopeDescription": "read scope"}],
                },
            },
        },
        "Outputs": {"ResourceServerRef": {"Value": {"Ref": "ResourceServer"}}},
    })


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A stack declaring AWS::Cognito::UserPoolResourceServer with an Identifier already taken in
    the pool rolls back with CloudFormation's validation error, leaving the original untouched;
    the same template with a fresh Identifier reaches CREATE_COMPLETE in the same pool."""
    cfn, cognito = ctx.client("cloudformation"), ctx.client("cognito-idp")
    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-behav-cogrsduppool-"), UserPoolTags={"sim2real": CHECK}
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    identifier = f"https://{ctx.unique_name('sim2real-behav-cogrsdupid-')}.example.com"
    original_name = ctx.unique_name("sim2real-behav-cogrsdupname-")
    cognito.create_resource_server(
        UserPoolId=pool_id, Identifier=identifier, Name=original_name,
        Scopes=[{"ScopeName": "orig", "ScopeDescription": "original scope"}],
    )

    duplicate_stack_name = ctx.unique_name("sim2real-behav-cogrsdupstack-")
    duplicate_stack_id = create_stack(
        ctx, cfn, duplicate_stack_name,
        _template(pool_id=pool_id, identifier=identifier,
                  name=ctx.unique_name("sim2real-behav-cogrsdupname2-")),
    )
    status = wait_stack(cfn, duplicate_stack_id)
    assert status == "ROLLBACK_COMPLETE", f"duplicate-Identifier stack ended {status!r}"

    failed = [
        (e["LogicalResourceId"], e.get("ResourceStatusReason"))
        for e in stack_events(cfn, duplicate_stack_id)
        if e["ResourceStatus"] == "CREATE_FAILED"
    ]
    expected_reason = (
        "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list "
        "of issues with resource and property details, resolve each error, then retry the "
        "operation."
    )
    assert failed == [(duplicate_stack_name, expected_reason)], (
        f"expected exactly one CREATE_FAILED event on the stack itself with reason "
        f"{expected_reason!r}, got {failed!r}"
    )

    original = cognito.describe_resource_server(
        UserPoolId=pool_id, Identifier=identifier
    )["ResourceServer"]
    assert original["Name"] == original_name, (
        f"the rolled-back stack changed the original resource server's Name: "
        f"expected {original_name!r}, got {original['Name']!r}"
    )

    fresh_identifier = f"https://{ctx.unique_name('sim2real-behav-cogrsfreshid-')}.example.com"
    fresh_stack_id = create_stack(
        ctx, cfn, ctx.unique_name("sim2real-behav-cogrsfreshstack-"),
        _template(pool_id=pool_id, identifier=fresh_identifier,
                  name=ctx.unique_name("sim2real-behav-cogrsfreshname-")),
    )
    status = wait_stack(cfn, fresh_stack_id)
    assert status == "CREATE_COMPLETE", f"fresh-Identifier stack ended {status!r}"
    fresh = cognito.describe_resource_server(
        UserPoolId=pool_id, Identifier=fresh_identifier
    )["ResourceServer"]
    assert fresh["Identifier"] == fresh_identifier, (
        f"expected the fresh stack's resource server Identifier {fresh_identifier!r}, "
        f"got {fresh['Identifier']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
