"""deploy-devicefarm-devicepool-networkprofile-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-devicefarm-devicepool-networkprofile-round-trip"
GROUP = "deploy"
SERVICES = ["cloudformation", "devicefarm"]

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


# ---- Check-specific: the template, then run(). ----

_RULE = {"Attribute": "PLATFORM", "Operator": "EQUALS", "Value": '"ANDROID"'}
_RULE_API = {"attribute": "PLATFORM", "operator": "EQUALS", "value": '"ANDROID"'}


def _template(project_name, pool_name, profile_name, with_children=True):
    resources = {
        "Proj": {"Type": "AWS::DeviceFarm::Project", "Properties": {"Name": project_name}},
    }
    if with_children:
        resources["Profile"] = {"Type": "AWS::DeviceFarm::NetworkProfile", "Properties": {
            "Name": profile_name,
            "ProjectArn": {"Fn::GetAtt": ["Proj", "Arn"]},
            "Description": "sim2real network profile",
            "DownlinkBandwidthBits": 104857600,
            "UplinkBandwidthBits": 104857600,
            "Tags": [{"Key": "sim2real-np", "Value": profile_name}],
        }}
        resources["Pool"] = {"Type": "AWS::DeviceFarm::DevicePool", "Properties": {
            "Name": pool_name,
            "ProjectArn": {"Fn::GetAtt": ["Proj", "Arn"]},
            "Description": "sim2real device pool",
            "Rules": [_RULE],
            "Tags": [{"Key": "sim2real-pool", "Value": pool_name}],
        }}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": {
            "ProjRef": {"Value": {"Ref": "Proj"}},
            **({"ProfileRef": {"Value": {"Ref": "Profile"}},
                "ProfileArn": {"Value": {"Fn::GetAtt": ["Profile", "Arn"]}},
                "PoolRef": {"Value": {"Ref": "Pool"}},
                "PoolArn": {"Value": {"Fn::GetAtt": ["Pool", "Arn"]}}} if with_children else {}),
        },
    })


def _own_tags(df, arn):
    raw = df.list_tags_for_resource(ResourceARN=arn)["Tags"]
    return {t["Key"]: t["Value"] for t in raw if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Device Farm device pool and network profile read back through Device Farm;
    an update dropping both removes them from the project, and deleting the stack removes it.
    """
    cf = ctx.client("cloudformation")
    df = ctx.client("devicefarm")
    stack = ctx.unique_name("sim2real-cfndf-pool-")
    project = ctx.unique_name("sim2real-cfndf-pool-proj-")
    pool = ctx.unique_name("sim2real-cfndf-pool-pool-")
    profile = ctx.unique_name("sim2real-cfndf-pool-np-")

    stack_id = create_stack(ctx, cf, stack, _template(project, pool, profile))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)

    pools = paginate(df, "list_device_pools", "devicePools", arn=out["ProjRef"], type="PRIVATE")
    matched = [p for p in pools if p["name"] == pool]
    assert [p["arn"] for p in matched] == [out["PoolRef"]], (
        f"ListDevicePools found {matched!r} for name {pool!r}, Ref was {out['PoolRef']!r}"
    )
    got_pool = df.get_device_pool(arn=out["PoolRef"])["devicePool"]
    assert (out["PoolArn"], got_pool["arn"]) == (out["PoolRef"], out["PoolRef"]), (
        f"GetAtt Arn {out['PoolArn']!r} and Ref {out['PoolRef']!r} must both equal the pool arn"
    )
    got = {k: got_pool[k] for k in ("name", "description", "rules")}
    assert got == {"name": pool, "description": "sim2real device pool", "rules": [_RULE_API]}, (
        f"device pool {got!r}"
    )

    profiles = paginate(df, "list_network_profiles", "networkProfiles",
                        arn=out["ProjRef"], type="PRIVATE")
    matched = [p for p in profiles if p["name"] == profile]
    assert [p["arn"] for p in matched] == [out["ProfileRef"]], (
        f"ListNetworkProfiles found {matched!r} for name {profile!r}, Ref was {out['ProfileRef']!r}"
    )
    got_profile = df.get_network_profile(arn=out["ProfileRef"])["networkProfile"]
    assert (out["ProfileArn"], got_profile["arn"]) == (out["ProfileRef"], out["ProfileRef"]), (
        f"GetAtt Arn {out['ProfileArn']!r} and Ref {out['ProfileRef']!r} must both equal the arn"
    )
    got = {k: got_profile[k] for k in (
        "name", "description", "downlinkBandwidthBits", "uplinkBandwidthBits",
    )}
    assert got == {
        "name": profile, "description": "sim2real network profile",
        "downlinkBandwidthBits": 104857600, "uplinkBandwidthBits": 104857600,
    }, f"network profile {got!r}"
    got = (_own_tags(df, out["PoolRef"]), _own_tags(df, out["ProfileRef"]))
    assert got == ({"sim2real": stack, "sim2real-pool": pool},
                   {"sim2real": stack, "sim2real-np": profile}), f"pool/profile tags {got!r}"
    projects = [p["arn"] for p in paginate(df, "list_projects", "projects") if p["name"] == project]
    assert projects == [out["ProjRef"]], f"ListProjects for {project!r}: {projects!r}"

    # Children before parent: the update drops the pool and the network profile; each answers its
    # own NotFoundException while the same project still answers.
    cf.update_stack(
        StackName=stack_id, TemplateBody=_template(project, pool, profile, with_children=False),
    )
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"
    refused = ("NotFoundException", f"No devicepool found for arn {out['PoolRef']}")
    expect_error(lambda: df.get_device_pool(arn=out["PoolRef"]), *refused)
    refused = ("NotFoundException", f"No networkprofile found for arn {out['ProfileRef']}")
    expect_error(lambda: df.get_network_profile(arn=out["ProfileRef"]), *refused)
    still_project = df.get_project(arn=out["ProjRef"])["project"]
    assert still_project["arn"] == out["ProjRef"], (
        f"project {out['ProjRef']!r} must still answer after dropping the pool"
    )

    delete_stack(cf, stack_id)
    refused = ("NotFoundException", f"No project was found for arn {out['ProjRef']}")
    expect_error(lambda: df.get_project(arn=out["ProjRef"]), *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
