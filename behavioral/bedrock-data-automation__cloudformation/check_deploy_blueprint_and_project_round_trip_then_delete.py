"""deploy-blueprint-and-project-round-trip-then-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-blueprint-and-project-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["bedrock-data-automation", "cloudformation"]

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

_SCHEMA = {
    "$schema": "http://json-schema.org/draft-07/schema#",
    "description": "sim2real provisioning-sweep probe schema",
    "class": "sim2real-probe-document",
    "type": "object",
    "properties": {
        "field_one": {"type": "string", "inferenceType": "explicit",
                       "instruction": "extract field one"},
    },
}

_PROJECT_NOT_FOUND = ("ResourceNotFoundException", "Project Arn not found.")
_BLUEPRINT_NOT_FOUND = ("ResourceNotFoundException", "Blueprint Arn not found.")

_STANDARD_OUTPUT_CONFIG = {
    "Document": {
        "Extraction": {
            "Granularity": {"Types": ["DOCUMENT"]},
            "BoundingBox": {"State": "DISABLED"},
        },
        "GenerativeField": {"State": "DISABLED"},
        "OutputFormat": {
            "TextFormat": {"Types": ["PLAIN_TEXT"]},
            "AdditionalFileFormat": {"State": "DISABLED"},
        },
    },
}


def _template(project_name: str, blueprint_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Project": {
                "Type": "AWS::Bedrock::DataAutomationProject",
                "Properties": {
                    "ProjectName": project_name,
                    "StandardOutputConfiguration": _STANDARD_OUTPUT_CONFIG,
                },
            },
            "Blueprint": {
                "Type": "AWS::Bedrock::Blueprint",
                "Properties": {
                    "BlueprintName": blueprint_name,
                    "Type": "DOCUMENT",
                    "Schema": _SCHEMA,
                },
            },
        },
        "Outputs": {
            "ProjectArn": {"Value": {"Ref": "Project"}},
            "BlueprintArn": {"Value": {"Ref": "Blueprint"}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation DataAutomationProject and Blueprint read back as templated.

    Refs match independent listings, every templated property reads back, and deleting the stack
    removes both, each answering its own NotFound.
    """
    cfn = ctx.client("cloudformation")
    bda = ctx.client("bedrock-data-automation")
    stack = ctx.unique_name("sim2real-cfnbda-")
    project_name = ctx.unique_name("sim2real-bdaproj-")
    blueprint_name = ctx.unique_name("sim2real-bdabp-")

    stack_id = create_stack(ctx, cfn, stack, _template(project_name, blueprint_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )

    out = stack_outputs(cfn, stack_id)
    project_arn, blueprint_arn = out["ProjectArn"], out["BlueprintArn"]

    # Ref against an independent read (ListDataAutomationProjects by name), not a read keyed by Ref.
    projects = paginate(bda, "list_data_automation_projects", "projects")
    pmatches = [p for p in projects if p["projectName"] == project_name]
    assert len(pmatches) == 1, f"ListDataAutomationProjects found {pmatches!r} for {project_name!r}"
    assert pmatches[0]["projectArn"] == project_arn, (
        f"ListDataAutomationProjects arn {pmatches[0]['projectArn']!r} != {project_arn!r}"
    )

    deadline = time.monotonic() + 120.0
    project = None
    while time.monotonic() < deadline:
        project = bda.get_data_automation_project(projectArn=project_arn)["project"]
        if project["status"] in ("COMPLETED", "FAILED"):
            break
        time.sleep(3)
    assert project["status"] == "COMPLETED", (
        f"project {project_arn!r} never reached COMPLETED, last status {project['status']!r}"
    )
    assert project["projectName"] == project_name, (
        f"GetDataAutomationProject name {project['projectName']!r} != {project_name!r}"
    )
    doc = project["standardOutputConfiguration"]["document"]
    got_config = (doc["extraction"]["granularity"]["types"],
                  doc["extraction"]["boundingBox"]["state"], doc["generativeField"]["state"],
                  doc["outputFormat"]["textFormat"]["types"],
                  doc["outputFormat"]["additionalFileFormat"]["state"])
    want_config = (["DOCUMENT"], "DISABLED", "DISABLED", ["PLAIN_TEXT"], "DISABLED")
    assert got_config == want_config, (
        f"templated StandardOutputConfiguration read back as {got_config!r}, "
        f"expected {want_config!r}"
    )

    blueprints = paginate(bda, "list_blueprints", "blueprints")
    bmatches = [b for b in blueprints if b["blueprintName"] == blueprint_name]
    assert len(bmatches) == 1, f"ListBlueprints found {bmatches!r} for {blueprint_name!r}"
    assert bmatches[0]["blueprintArn"] == blueprint_arn, (
        f"ListBlueprints arn {bmatches[0]['blueprintArn']!r} != {blueprint_arn!r}"
    )

    blueprint = bda.get_blueprint(blueprintArn=blueprint_arn)["blueprint"]
    assert blueprint["blueprintName"] == blueprint_name, (
        f"GetBlueprint name {blueprint['blueprintName']!r} != {blueprint_name!r}"
    )
    assert blueprint["type"] == "DOCUMENT", f"GetBlueprint type {blueprint['type']!r} != DOCUMENT"
    got_schema = json.loads(blueprint["schema"])
    assert got_schema == _SCHEMA, f"GetBlueprint schema {got_schema!r} != templated {_SCHEMA!r}"

    delete_stack(cfn, stack_id)

    expect_error(lambda: bda.get_data_automation_project(projectArn=project_arn),
                *_PROJECT_NOT_FOUND)
    expect_error(lambda: bda.get_blueprint(blueprintArn=blueprint_arn), *_BLUEPRINT_NOT_FOUND)

    remaining_projects = paginate(bda, "list_data_automation_projects", "projects")
    assert project_name not in {p["projectName"] for p in remaining_projects}, (
        f"{project_name!r} still listed by ListDataAutomationProjects after the stack delete"
    )
    remaining_blueprints = paginate(bda, "list_blueprints", "blueprints")
    assert blueprint_name not in {b["blueprintName"] for b in remaining_blueprints}, (
        f"{blueprint_name!r} still listed by ListBlueprints after the stack delete"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
