"""deploy-ec2-verified-access-lifecycle."""

from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-ec2-verified-access-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

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


_POLICY_DOC = "permit(principal, action, resource) when { context.sim2real.ok == true };"
_SCOPE = "openid"
_OIDC = {
    "Issuer": "https://sim2real.example.com/oidc",
    "AuthorizationEndpoint": "https://sim2real.example.com/authorize",
    "TokenEndpoint": "https://sim2real.example.com/token",
    "UserInfoEndpoint": "https://sim2real.example.com/userinfo",
    "ClientId": "sim2real-client-id",
    "Scope": _SCOPE,
}

def _template(tag: str, policy_ref: str, client_secret: str) -> str:
    t = [{"Key": "sim2real-res", "Value": tag}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TrustProvider": {
                "Type": "AWS::EC2::VerifiedAccessTrustProvider",
                "Properties": {
                    "TrustProviderType": "user",
                    "UserTrustProviderType": "oidc",
                    "PolicyReferenceName": policy_ref,
                    "OidcOptions": {**_OIDC, "ClientSecret": client_secret},
                    "Tags": t,
                },
            },
            "Instance": {
                "Type": "AWS::EC2::VerifiedAccessInstance",
                "Properties": {
                    "Description": tag,
                    "VerifiedAccessTrustProviderIds": [{"Ref": "TrustProvider"}],
                    "Tags": t,
                },
            },
            "Group": {
                "Type": "AWS::EC2::VerifiedAccessGroup",
                "Properties": {
                    "VerifiedAccessInstanceId": {"Ref": "Instance"},
                    "PolicyDocument": _POLICY_DOC,
                    "PolicyEnabled": True,
                    "Tags": t,
                },
            },
        },
        "Outputs": {
            "TrustProviderId": {"Value": {"Ref": "TrustProvider"}},
            "TrustProviderCreationTime": {"Value": {"Fn::GetAtt": ["TrustProvider", "CreationTime"]}},
            "InstanceId": {"Value": {"Ref": "Instance"}},
            "InstanceCreationTime": {"Value": {"Fn::GetAtt": ["Instance", "CreationTime"]}},
            "GroupId": {"Value": {"Ref": "Group"}},
            "GroupArn": {"Value": {"Fn::GetAtt": ["Group", "VerifiedAccessGroupArn"]}},
            "GroupCreationTime": {"Value": {"Fn::GetAtt": ["Group", "CreationTime"]}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Verified Access trust provider, instance and group CloudFormation declares are each a
    real EC2 Verified Access object: the instance is really attached to the trust provider, the
    group's policy is really stored, and DeleteStack removes all three from the EC2 API.
    """
    cfn = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")

    name = ctx.unique_name("sim2real-xsvc-va-")
    # PolicyReferenceName must match [a-zA-Z_][a-zA-Z0-9_]* -- no hyphens.
    policy_ref = ctx.unique_name("sim2real_va_policy_")
    stack_id = create_stack(
        ctx, cfn, name, _template(name, policy_ref, ctx.unique_name("sim2real-va-secret-")))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"verified-access stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    tag = {"Key": "sim2real-res", "Value": name}
    tp_id, inst_id, grp_id = out["TrustProviderId"], out["InstanceId"], out["GroupId"]

    # 1. the trust provider Ref is its primary identifier, and its own type and policy name read
    # back from EC2, not just from the template.
    tp = ec2.describe_verified_access_trust_providers(
        VerifiedAccessTrustProviderIds=[tp_id])["VerifiedAccessTrustProviders"][0]
    assert tp["VerifiedAccessTrustProviderId"] == tp_id, (
        f"Ref {tp_id!r} does not match the trust provider id EC2 reports: "
        f"{tp['VerifiedAccessTrustProviderId']!r}"
    )
    assert (tp["TrustProviderType"], tp["UserTrustProviderType"], tp["PolicyReferenceName"]) == (
        "user", "oidc", policy_ref
    ), (
        f"trust provider read back as {(tp['TrustProviderType'], tp['UserTrustProviderType'], tp['PolicyReferenceName'])!r}, "
        f"expected ('user', 'oidc', {policy_ref!r})"
    )
    oidc = {k: tp["OidcOptions"].get(k) for k in _OIDC}  # ClientSecret is write-only
    assert oidc == _OIDC, f"trust provider OidcOptions {oidc!r}, expected {_OIDC!r}"
    assert tag in tp.get("Tags", []), f"trust provider tags {tp.get('Tags')!r}"
    assert tp["CreationTime"] == out["TrustProviderCreationTime"], (
        f"GetAtt CreationTime {out['TrustProviderCreationTime']!r} disagrees with "
        f"DescribeVerifiedAccessTrustProviders {tp['CreationTime']!r}"
    )

    # 2. the instance Ref is its primary identifier, its Description round-trips, and it is
    # really attached to the trust provider (not merely two unrelated objects).
    inst = ec2.describe_verified_access_instances(
        VerifiedAccessInstanceIds=[inst_id])["VerifiedAccessInstances"][0]
    assert inst["VerifiedAccessInstanceId"] == inst_id, (
        f"Ref {inst_id!r} does not match the instance id EC2 reports: {inst['VerifiedAccessInstanceId']!r}"
    )
    assert tag in inst.get("Tags", []), f"instance tags {inst.get('Tags')!r}"
    assert inst["Description"] == name, (
        f"instance Description is {inst['Description']!r}, expected the template's {name!r}"
    )
    attached = {p["VerifiedAccessTrustProviderId"] for p in inst.get("VerifiedAccessTrustProviders", [])}
    assert attached == {tp_id}, (
        f"instance {inst_id!r} has trust providers {attached!r}, expected it attached to {tp_id!r} "
        f"via VerifiedAccessTrustProviderIds"
    )
    assert inst["CreationTime"] == out["InstanceCreationTime"], (
        f"GetAtt CreationTime {out['InstanceCreationTime']!r} disagrees with "
        f"DescribeVerifiedAccessInstances {inst['CreationTime']!r}"
    )

    # 3. the group Ref is its primary identifier, points at the instance, and its policy (a
    # property the template set but DescribeVerifiedAccessGroups does not itself return) is
    # really stored.
    grp = ec2.describe_verified_access_groups(
        VerifiedAccessGroupIds=[grp_id])["VerifiedAccessGroups"][0]
    assert grp["VerifiedAccessGroupId"] == grp_id, (
        f"Ref {grp_id!r} does not match the group id EC2 reports: {grp['VerifiedAccessGroupId']!r}"
    )
    assert tag in grp.get("Tags", []), f"group tags {grp.get('Tags')!r}"
    assert grp["VerifiedAccessInstanceId"] == inst_id, (
        f"group {grp_id!r} belongs to instance {grp['VerifiedAccessInstanceId']!r}, expected {inst_id!r}"
    )
    assert grp["VerifiedAccessGroupArn"] == out["GroupArn"], (
        f"GetAtt VerifiedAccessGroupArn {out['GroupArn']!r} disagrees with "
        f"DescribeVerifiedAccessGroups {grp['VerifiedAccessGroupArn']!r}"
    )
    assert grp["CreationTime"] == out["GroupCreationTime"], (
        f"GetAtt CreationTime {out['GroupCreationTime']!r} disagrees with "
        f"DescribeVerifiedAccessGroups {grp['CreationTime']!r}"
    )
    policy = ec2.get_verified_access_group_policy(VerifiedAccessGroupId=grp_id)
    assert (policy["PolicyEnabled"], policy["PolicyDocument"]) == (True, _POLICY_DOC), (
        f"GetVerifiedAccessGroupPolicy returned {(policy['PolicyEnabled'], policy['PolicyDocument'])!r}, "
        f"expected (True, {_POLICY_DOC!r})"
    )

    # 4. DeleteStack removes all three objects from the EC2 API, each with its exact NotFound.
    delete_stack(cfn, stack_id)
    expect_error(lambda: ec2.describe_verified_access_groups(VerifiedAccessGroupIds=[grp_id]),
                 *("InvalidVerifiedAccessGroupId.NotFound",
                 f"VerifiedAccessGroup {grp_id} does not exist"))
    expect_error(
        lambda: ec2.describe_verified_access_instances(VerifiedAccessInstanceIds=[inst_id]),
        *("InvalidVerifiedAccessInstanceId.NotFound", f"VerifiedAccessInstance {inst_id} does not exist"))
    expect_error(
        lambda: ec2.describe_verified_access_trust_providers(VerifiedAccessTrustProviderIds=[tp_id]),
        *("InvalidVerifiedAccessTrustProviderId.NotFound",
        f"VerifiedAccessTrustProvider {tp_id} does not exist"))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
