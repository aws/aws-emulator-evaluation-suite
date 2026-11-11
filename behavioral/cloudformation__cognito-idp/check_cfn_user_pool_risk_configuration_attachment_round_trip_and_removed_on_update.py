"""cfn-user-pool-risk-configuration-attachment-round-trip-and-removed-on-update."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "cfn-user-pool-risk-configuration-attachment-round-trip-and-removed-on-update"
GROUP = "deploy"
SERVICES = ["cloudformation", "cognito-idp"]

# ---- CloudFormation helpers ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


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
    """Delete by StackId within one deadline; raise unless DELETE_COMPLETE. Safe to call twice.

    A stack still creating or updating is first waited out; a failure names each resource's reason.
    """
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
        events = stack_events(cf, stack_id)
        starts = [i for i, e in enumerate(events) if e.get("PhysicalResourceId") == stack_id
                  and e["ResourceStatus"] == "DELETE_IN_PROGRESS"]
        failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
                  for e in events[starts[-1] if starts else 0:]
                  if e["ResourceStatus"] == "DELETE_FAILED"]
        raise AssertionError(f"stack {stack_id} delete ended {status!r}: {failed!r}")


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


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


def decisive_rows(events, *logical_ids):
    """``(logical id, status)`` of each non-IN_PROGRESS row, oldest first (subsequence asserts)."""
    return [
        (e["LogicalResourceId"], e["ResourceStatus"]) for e in events
        if not e["ResourceStatus"].endswith("_IN_PROGRESS")
        and (not logical_ids or e["LogicalResourceId"] in logical_ids)
    ]


# ---- Check-specific: the template, then run(). ----

def _template(*, with_risk: bool, pool_name: str, client_name: str) -> str:
    resources = {
        "Pool": {
            "Type": "AWS::Cognito::UserPool",
            "Properties": {"UserPoolName": pool_name, "UserPoolTier": "PLUS"},
        },
        "Client": {
            "Type": "AWS::Cognito::UserPoolClient",
            "Properties": {"UserPoolId": {"Ref": "Pool"}, "ClientName": client_name},
        },
    }
    outputs = {"PoolRef": {"Value": {"Ref": "Pool"}}, "ClientRef": {"Value": {"Ref": "Client"}}}
    if with_risk:
        resources["Risk"] = {
            "Type": "AWS::Cognito::UserPoolRiskConfigurationAttachment",
            "Properties": {
                "UserPoolId": {"Ref": "Pool"},
                "ClientId": "ALL",
                "CompromisedCredentialsRiskConfiguration": {"Actions": {"EventAction": "BLOCK"}},
            },
        }
        outputs["RiskRef"] = {"Value": {"Ref": "Risk"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation UserPoolRiskConfigurationAttachment on a PLUS pool reads back, then is removed.

    Its Ref is the listed pool's Id|ALL and DescribeRiskConfiguration reports every templated value;
    the update drops the configuration while the same pool and client remain.
    """
    cfn, cognito = ctx.client("cloudformation"), ctx.client("cognito-idp")
    pool_name = ctx.unique_name("sim2real-behav-cogriskpool-")
    client_name = ctx.unique_name("sim2real-behav-cogriskclient-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cogriskstack-"),
                            _template(with_risk=True, pool_name=pool_name, client_name=client_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    pools = [p["Id"] for p in paginate(cognito, "list_user_pools", "UserPools", MaxResults=60)
             if p["Name"] == pool_name]
    assert pools == [out["PoolRef"]], f"user pools named {pool_name!r}: {pools!r}"
    pool_id = pools[0]
    assert out["RiskRef"] == f"{pool_id}|ALL", f"risk attachment Ref {out['RiskRef']!r}"
    pool = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]
    client = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=out["ClientRef"])[
        "UserPoolClient"]
    assert (pool["UserPoolTier"], client["ClientName"]) == ("PLUS", client_name), (
        f"pool tier {pool['UserPoolTier']!r}, client name {client['ClientName']!r}"
    )

    config = cognito.describe_risk_configuration(UserPoolId=pool_id, ClientId="ALL")[
        "RiskConfiguration"]
    got = (config["UserPoolId"], config.get("ClientId"),
           config["CompromisedCredentialsRiskConfiguration"]["Actions"])
    assert got == (pool_id, "ALL", {"EventAction": "BLOCK"}), f"DescribeRiskConfiguration {got!r}"

    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(with_risk=False, pool_name=pool_name, client_name=client_name))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"risk-dropping update ended {status!r}"
    after = cognito.describe_risk_configuration(UserPoolId=pool_id, ClientId="ALL")
    assert "RiskConfiguration" not in after, f"RiskConfiguration after the update: {after!r}"
    pool_after = cognito.describe_user_pool(UserPoolId=pool_id)["UserPool"]["CreationDate"]
    client_after = cognito.describe_user_pool_client(UserPoolId=pool_id, ClientId=out["ClientRef"])[
        "UserPoolClient"]["CreationDate"]
    assert (pool_after, client_after) == (pool["CreationDate"], client["CreationDate"]), (
        "the pool or client was replaced across the update"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
