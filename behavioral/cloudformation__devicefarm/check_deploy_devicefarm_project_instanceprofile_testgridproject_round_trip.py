"""deploy-devicefarm-project-instanceprofile-testgridproject-round-trip."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-devicefarm-project-instanceprofile-testgridproject-round-trip"
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

def _template(project_name, profile_name, grid_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Proj": {"Type": "AWS::DeviceFarm::Project", "Properties": {
                "Name": project_name,
                "DefaultJobTimeoutMinutes": 45,
                "Tags": [{"Key": "sim2real-proj", "Value": project_name}],
            }},
            "Profile": {"Type": "AWS::DeviceFarm::InstanceProfile", "Properties": {
                "Name": profile_name,
                "Description": "sim2real instance profile",
                "PackageCleanup": True,
                "RebootAfterUse": True,
                "Tags": [{"Key": "sim2real-profile", "Value": profile_name}],
            }},
            "Grid": {"Type": "AWS::DeviceFarm::TestGridProject", "Properties": {
                "Name": grid_name,
                "Description": "sim2real test grid project",
                "Tags": [{"Key": "sim2real-grid", "Value": grid_name}],
            }},
        },
        "Outputs": {
            "ProjRef": {"Value": {"Ref": "Proj"}},
            "ProjArn": {"Value": {"Fn::GetAtt": ["Proj", "Arn"]}},
            "ProfileRef": {"Value": {"Ref": "Profile"}},
            "ProfileArn": {"Value": {"Fn::GetAtt": ["Profile", "Arn"]}},
            "GridRef": {"Value": {"Ref": "Grid"}},
            "GridArn": {"Value": {"Fn::GetAtt": ["Grid", "Arn"]}},
        },
    })


def paginate_by_token(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``, which has no botocore paginator."""
    items, token = [], None
    while True:
        page = getattr(client, op)(**({"nextToken": token} if token else {}), **kw)
        items.extend(page.get(key, []))
        token = page.get("nextToken")
        if not token:
            return items


def _own_tags(df, arn):
    raw = {t["Key"]: t["Value"] for t in df.list_tags_for_resource(ResourceARN=arn)["Tags"]}
    return {k: v for k, v in raw.items() if not k.startswith("aws:")}


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Device Farm project, instance profile and test grid project read back
    through Device Farm with their properties and tags, and each is gone after the stack deletes.
    """
    cf = ctx.client("cloudformation")
    df = ctx.client("devicefarm")
    stack = ctx.unique_name("sim2real-cfndf-rt-")
    project = ctx.unique_name("sim2real-cfndf-rt-proj-")
    profile = ctx.unique_name("sim2real-cfndf-rt-prof-")
    grid = ctx.unique_name("sim2real-cfndf-rt-grid-")

    stack_id = create_stack(ctx, cf, stack, _template(project, profile, grid))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)

    # Ref against an independent, fully paginated read (ListProjects filtered to our own name),
    # never a read keyed by the Ref.
    projects = paginate(df, "list_projects", "projects")
    matched = [p for p in projects if p["name"] == project]
    assert [p["arn"] for p in matched] == [out["ProjRef"]], (
        f"ListProjects found {matched!r} for name {project!r}, Ref was {out['ProjRef']!r}"
    )
    got_project = df.get_project(arn=out["ProjRef"])["project"]
    assert (out["ProjArn"], got_project["arn"]) == (out["ProjRef"], out["ProjRef"]), (
        f"GetAtt Arn {out['ProjArn']!r} and Ref {out['ProjRef']!r} must both equal the project arn"
    )
    assert got_project["name"] == project, f"project name {got_project['name']!r} != {project!r}"
    assert got_project["defaultJobTimeoutMinutes"] == 45, (
        f"defaultJobTimeoutMinutes {got_project['defaultJobTimeoutMinutes']!r} != 45"
    )
    assert _own_tags(df, out["ProjRef"]) == {"sim2real": stack, "sim2real-proj": project}, (
        f"project tags {_own_tags(df, out['ProjRef'])!r}"
    )

    instance_profiles = paginate(df, "list_instance_profiles", "instanceProfiles")
    matched = [p for p in instance_profiles if p["name"] == profile]
    assert [p["arn"] for p in matched] == [out["ProfileRef"]], (
        f"ListInstanceProfiles found {matched!r} for name {profile!r}, Ref was {out['ProfileRef']!r}"
    )
    got_profile = df.get_instance_profile(arn=out["ProfileRef"])["instanceProfile"]
    assert (out["ProfileArn"], got_profile["arn"]) == (out["ProfileRef"], out["ProfileRef"]), (
        f"GetAtt Arn {out['ProfileArn']!r} and Ref {out['ProfileRef']!r} must both equal the arn"
    )
    got = {k: got_profile[k] for k in ("name", "description", "packageCleanup", "rebootAfterUse")}
    assert got == {
        "name": profile, "description": "sim2real instance profile",
        "packageCleanup": True, "rebootAfterUse": True,
    }, f"instance profile {got!r}"
    assert _own_tags(df, out["ProfileRef"]) == {"sim2real": stack, "sim2real-profile": profile}, (
        f"instance profile tags {_own_tags(df, out['ProfileRef'])!r}"
    )

    grids = paginate_by_token(df, "list_test_grid_projects", "testGridProjects")
    matched = [g for g in grids if g["name"] == grid]
    assert [g["arn"] for g in matched] == [out["GridRef"]], (
        f"ListTestGridProjects found {matched!r} for name {grid!r}, Ref was {out['GridRef']!r}"
    )
    got_grid = df.get_test_grid_project(projectArn=out["GridRef"])["testGridProject"]
    assert (out["GridArn"], got_grid["arn"]) == (out["GridRef"], out["GridRef"]), (
        f"GetAtt Arn {out['GridArn']!r} and Ref {out['GridRef']!r} must both equal the grid arn"
    )
    got = {k: got_grid[k] for k in ("name", "description")}
    assert got == {"name": grid, "description": "sim2real test grid project"}, f"grid {got!r}"
    assert _own_tags(df, out["GridRef"]) == {"sim2real": stack, "sim2real-grid": grid}, (
        f"test grid project tags {_own_tags(df, out['GridRef'])!r}"
    )

    delete_stack(cf, stack_id)
    refused = ("NotFoundException", f"No project was found for arn {out['ProjRef']}")
    expect_error(lambda: df.get_project(arn=out["ProjRef"]), *refused)
    refused = ("NotFoundException", f"No Instance Profile found for arn {out['ProfileRef']}")
    expect_error(lambda: df.get_instance_profile(arn=out["ProfileRef"]), *refused)
    refused = ("NotFoundException", f"The provided resource does not exist: {out['GridRef']}")
    expect_error(lambda: df.get_test_grid_project(projectArn=out["GridRef"]), *refused)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
