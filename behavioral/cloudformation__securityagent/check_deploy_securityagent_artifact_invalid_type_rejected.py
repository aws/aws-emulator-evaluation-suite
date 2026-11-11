"""deploy-securityagent-artifact-invalid-type-rejected."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags

CHECK = "deploy-securityagent-artifact-invalid-type-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "securityagent"]

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


def failed_reason(events, logical_id, status="CREATE_FAILED"):
    """The reason on the single ``status`` row of ``logical_id``: never an *_IN_PROGRESS row."""
    rows = [e.get("ResourceStatusReason") for e in events
            if e["LogicalResourceId"] == logical_id and e["ResourceStatus"] == status]
    assert len(rows) == 1, f"expected one {status} row for {logical_id}, got {rows!r}"
    return rows[0]


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# ---- Check-specific: the template, then run(). ----

_VALIDATION_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues "
    "with resource and property details, resolve each error, then retry the operation."
)


def _template(as_name: str, artifact_type: str, content_b64: str) -> str:
    return json.dumps({
        "Resources": {
            "AS": {"Type": "AWS::SecurityAgent::AgentSpace", "Properties": {"Name": as_name}},
            "Art": {
                "Type": "AWS::SecurityAgent::Artifact",
                "Properties": {
                    "AgentSpaceId": {"Ref": "AS"},
                    "ArtifactType": artifact_type,
                    "FileName": "sim2real-note.txt",
                    "ArtifactContent": content_b64,
                },
            },
        },
        "Outputs": {
            "ASRef": {"Value": {"Ref": "AS"}},
            "ArtRef": {"Value": {"Ref": "Art"}},
            "ArtArtifactId": {"Value": {"Fn::GetAtt": ["Art", "ArtifactId"]}},
        },
    })


def _agent_space_ids_named(sa, name: str) -> list[str]:
    """Ids of every listed agent space called ``name``, across all pages."""
    return [s["agentSpaceId"] for s in paginate(sa, "list_agent_spaces", "agentSpaceSummaries")
            if s["name"] == name]


_PAYLOAD = b"sim2real negative-control artifact payload"
_ENUM = "[TXT, PNG, JPEG, MD, PDF, DOCX, DOC, JSON, YAML]"


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::SecurityAgent::Artifact with an ArtifactType outside the registry's
    enum is rejected before any resource is created, and the stack rolls back; the identical
    template with a valid ArtifactType still deploys and reads back through SecurityAgent."""
    cf = ctx.client("cloudformation")
    sa = ctx.client("securityagent")
    content_b64 = base64.b64encode(_PAYLOAD).decode("ascii")

    bad_stack_name = ctx.unique_name("sim2real-behav-cfn-sa-art-bad-")
    bad_as_name = ctx.unique_name("sim2real-behav-cfn-sa-art-bad-")
    bad_stack_id = create_stack(ctx, cf, bad_stack_name, _template(bad_as_name, "EXE", content_b64))
    status = wait_stack(cf, bad_stack_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    reason = failed_reason(stack_events(cf, bad_stack_id), bad_stack_name)
    assert reason == _VALIDATION_REASON, f"expected the template-validation reason, got {reason!r}"

    found = validation_rows(cf, bad_stack_id)
    want = [("Art", "PROPERTY_VALIDATION", "FAILED", "FAIL",
             f"EXE is not a valid enum value. Supported values: {_ENUM}",
             "/Resources/Art/Properties/ArtifactType")]
    assert found == want, f"validation errors of the create: expected {want!r}, got {found!r}"

    resources = cf.describe_stack_resources(StackName=bad_stack_id)["StackResources"]
    assert resources == [], f"expected no resource to have been created, got {resources!r}"

    listed = _agent_space_ids_named(sa, bad_as_name)
    assert listed == [], (
        f"expected no agent space named {bad_as_name!r} after the rejection, ListAgentSpaces has {listed!r}"
    )

    # Positive control: the identical template, with a valid ArtifactType, deploys and reads back.
    good_stack_name = ctx.unique_name("sim2real-behav-cfn-sa-art-good-")
    good_as_name = ctx.unique_name("sim2real-behav-cfn-sa-art-good-")
    good_stack_id = create_stack(ctx, cf, good_stack_name,
                                 _template(good_as_name, "TXT", content_b64))
    good_status = wait_stack(cf, good_stack_id)
    assert good_status == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {good_status!r}: "
        f"{decisive_rows(stack_events(cf, good_stack_id))!r}"
    )

    outputs = stack_outputs(cf, good_stack_id)
    as_id = outputs["ASRef"]
    listed = _agent_space_ids_named(sa, good_as_name)
    assert listed == [as_id], f"ListAgentSpaces ids named {good_as_name!r}: {listed!r}, Ref {as_id!r}"
    artifact_id = outputs["ArtArtifactId"]
    partition = good_stack_id.split(":")[1]
    want_arn = (f"arn:{partition}:securityagent:{ctx.region}:{ctx.account}:agent-space/{as_id}"
                f"/artifact/{artifact_id}")
    assert outputs["ArtRef"] == want_arn, f"Ref of Art {outputs['ArtRef']!r}, expected {want_arn!r}"
    got_art = sa.get_artifact(agentSpaceId=as_id, artifactId=artifact_id)
    assert (got_art["artifact"]["type"], got_art["fileName"]) == ("TXT", "sim2real-note.txt"), (
        f"GetArtifact of the control: type {got_art['artifact']['type']!r}, fileName {got_art['fileName']!r}"
    )
    got_content = base64.b64decode(got_art["artifact"]["contents"])
    assert got_content == _PAYLOAD, f"GetArtifact content {got_content!r}, expected {_PAYLOAD!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
