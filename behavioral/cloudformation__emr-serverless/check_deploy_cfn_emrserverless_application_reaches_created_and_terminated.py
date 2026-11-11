"""deploy-cfn-emrserverless-application-reaches-created-and-terminated."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-emrserverless-application-reaches-created-and-terminated"
GROUP = "deploy"
SERVICES = ["cloudformation", "emr-serverless"]

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

def _template(name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Application": {
                "Type": "AWS::EMRServerless::Application",
                "Properties": {
                    "Name": name,
                    "ReleaseLabel": "emr-7.9.0",
                    "Type": "SPARK",
                    "AutoStartConfiguration": {"Enabled": False},
                },
            },
        },
        "Outputs": {
            "ApplicationRef": {"Value": {"Ref": "Application"}},
            "ApplicationArn": {"Value": {"Fn::GetAtt": ["Application", "Arn"]}},
            "ApplicationId": {"Value": {"Fn::GetAtt": ["Application", "ApplicationId"]}},
        },
    })


def _application_ids_named(emrs, name: str) -> list[str]:
    """Ids of every application ListApplications reports under ``name``, across all pages."""
    return [a["id"] for a in paginate(emrs, "list_applications", "applications")
            if a["name"] == name]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """An EMR Serverless application deployed by CloudFormation reads back through GetApplication
    with the properties and Fn::GetAtt attributes the template set, and settles at the TERMINATED
    state GetApplication itself reports once the stack that created it is deleted."""
    cfn = ctx.client("cloudformation")
    emrs = ctx.client("emr-serverless")
    stack_name = ctx.unique_name("sim2real-cfnemrs-")
    app_name = ctx.unique_name("sim2real-cfnemrs-app-")

    stack_id = create_stack(ctx, cfn, stack_name, _template(app_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack settled at {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    create_events = [
        e for e in stack_events(cfn, stack_id)
        if e["LogicalResourceId"] == "Application" and e["ResourceStatus"] == "CREATE_COMPLETE"
    ]
    assert len(create_events) == 1, (
        f"expected exactly one Application CREATE_COMPLETE event, got {create_events!r}"
    )

    outputs = stack_outputs(cfn, stack_id)
    physical_id = cfn.describe_stack_resource(
        StackName=stack_id, LogicalResourceId="Application"
    )["StackResourceDetail"]["PhysicalResourceId"]
    assert physical_id == outputs["ApplicationId"], (
        f"PhysicalResourceId {physical_id!r} != Fn::GetAtt ApplicationId {outputs['ApplicationId']!r}"
    )

    listed_ids = _application_ids_named(emrs, app_name)
    assert listed_ids == [outputs["ApplicationRef"]], (
        f"expected ListApplications to report exactly the Ref {outputs['ApplicationRef']!r} under "
        f"{app_name!r}, got {listed_ids!r}"
    )

    app = emrs.get_application(applicationId=physical_id)["application"]
    assert app["applicationId"] == physical_id, (
        f"GetApplication applicationId {app['applicationId']!r} != Ref/PhysicalResourceId {physical_id!r}"
    )
    assert app["arn"] == outputs["ApplicationArn"], (
        f"GetApplication arn {app['arn']!r} != stack output ApplicationArn {outputs['ApplicationArn']!r}"
    )
    assert app["name"] == app_name, f"GetApplication name {app['name']!r} != template Name {app_name!r}"
    assert app["releaseLabel"] == "emr-7.9.0", f"releaseLabel was {app['releaseLabel']!r}"
    assert app["type"] == "Spark", f"type was {app['type']!r}"
    assert app["state"] == "CREATED", f"state was {app['state']!r}, expected CREATED"
    assert app["autoStartConfiguration"]["enabled"] is False, (
        f"autoStartConfiguration was {app['autoStartConfiguration']!r}, expected enabled=False"
    )

    delete_stack(cfn, stack_id)

    delete_events = [
        e for e in stack_events(cfn, stack_id)
        if e["LogicalResourceId"] == "Application" and e["ResourceStatus"] == "DELETE_COMPLETE"
    ]
    assert len(delete_events) == 1, (
        f"expected exactly one Application DELETE_COMPLETE event, got {delete_events!r}"
    )

    # EMR Serverless soft-deletes: GetApplication keeps answering after DeleteApplication, with
    # the terminal state as the tombstone rather than a not-found error.
    gone_state = emrs.get_application(applicationId=physical_id)["application"]["state"]
    assert gone_state == "TERMINATED", (
        f"GetApplication after stack delete reported state {gone_state!r}, expected TERMINATED"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
