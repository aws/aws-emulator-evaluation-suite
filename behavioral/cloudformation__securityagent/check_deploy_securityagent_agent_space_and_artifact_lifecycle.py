"""deploy-securityagent-agent-space-and-artifact-lifecycle."""
from __future__ import annotations

import base64
import json
import time

from behavioral_harness import tags

CHECK = "deploy-securityagent-agent-space-and-artifact-lifecycle"
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


# ---- Check-specific: the template, then run(). ----


def _agent_space_ids_named(sa, name: str) -> list[str]:
    """Ids of every listed agent space called ``name``, across all pages."""
    return [s["agentSpaceId"] for s in paginate(sa, "list_agent_spaces", "agentSpaceSummaries")
            if s["name"] == name]


def _artifact_ids(sa, as_id: str) -> list[str]:
    """Ids of every artifact listed under agent space ``as_id``, across all pages."""
    return [a["artifactId"]
            for a in paginate(sa, "list_artifacts", "artifactSummaries", agentSpaceId=as_id)]


def _fmt(ts) -> str:
    return ts.strftime("%Y-%m-%dT%H:%M:%S.%fZ")


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation-deployed AgentSpace and its Artifact are real at SecurityAgent: Ref and GetAtt
    match the listed ids and timestamps, the content round-trips, dropping the Artifact deletes it
    under the live space, and deleting the stack removes the space."""
    cf = ctx.client("cloudformation")
    sa = ctx.client("securityagent")
    stack_name = ctx.unique_name("sim2real-behav-cfn-sa-as-")
    as_name = ctx.unique_name("sim2real-behav-cfn-sa-as-")
    description = "sim2real agent space provisioning check"
    file_name = "sim2real-note.txt"
    payload = b"sim2real artifact payload for a provisioning check"
    content_b64 = base64.b64encode(payload).decode("ascii")

    def template(with_artifact: bool) -> str:
        resources = {
            "AS": {
                "Type": "AWS::SecurityAgent::AgentSpace",
                "Properties": {"Name": as_name, "Description": description},
            },
        }
        outputs = {
            "ASRef": {"Value": {"Ref": "AS"}},
            "ASAgentSpaceId": {"Value": {"Fn::GetAtt": ["AS", "AgentSpaceId"]}},
            "ASCreatedAt": {"Value": {"Fn::GetAtt": ["AS", "CreatedAt"]}},
            "ASUpdatedAt": {"Value": {"Fn::GetAtt": ["AS", "UpdatedAt"]}},
        }
        if not with_artifact:
            return json.dumps({"Resources": resources, "Outputs": outputs})
        resources["Art"] = {
            "Type": "AWS::SecurityAgent::Artifact",
            "Properties": {
                "AgentSpaceId": {"Ref": "AS"},
                "ArtifactType": "TXT",
                "FileName": file_name,
                "ArtifactContent": content_b64,
            },
        }
        outputs["ArtRef"] = {"Value": {"Ref": "Art"}}
        outputs["ArtArtifactId"] = {"Value": {"Fn::GetAtt": ["Art", "ArtifactId"]}}
        return json.dumps({"Resources": resources, "Outputs": outputs})

    stack_id = create_stack(ctx, cf, stack_name, template(True))
    created = wait_stack(cf, stack_id)
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )

    outputs = stack_outputs(cf, stack_id)
    as_id = outputs["ASRef"]
    artifact_arn = outputs["ArtRef"]
    artifact_id = outputs["ArtArtifactId"]

    partition = stack_id.split(":")[1]
    expected_artifact_arn = (
        f"arn:{partition}:securityagent:{ctx.region}:{ctx.account}:agent-space/{as_id}"
        f"/artifact/{artifact_id}"
    )
    assert artifact_arn == expected_artifact_arn, (
        f"Ref of Art was {artifact_arn!r}, expected {expected_artifact_arn!r}"
    )

    listed = _agent_space_ids_named(sa, as_name)
    assert listed == [as_id] and outputs["ASAgentSpaceId"] == as_id, (
        f"ListAgentSpaces ids named {as_name!r} were {listed!r}; Ref {as_id!r}, "
        f"GetAtt AgentSpaceId {outputs['ASAgentSpaceId']!r}"
    )

    # Independent read at the owning service: SecurityAgent's own record of the agent space.
    got_as = sa.batch_get_agent_spaces(agentSpaceIds=[as_id])
    assert got_as["notFound"] == [], f"agent space {as_id!r} reported not found: {got_as['notFound']!r}"
    assert len(got_as["agentSpaces"]) == 1, f"expected one agent space, got {got_as['agentSpaces']!r}"
    as_record = got_as["agentSpaces"][0]
    assert as_record["name"] == as_name, f"BatchGetAgentSpaces name {as_record['name']!r}"
    assert as_record["description"] == description, (
        f"BatchGetAgentSpaces description {as_record['description']!r}, expected {description!r}"
    )
    created_at = _fmt(as_record["createdAt"])
    assert created_at == outputs["ASCreatedAt"], (
        f"BatchGetAgentSpaces createdAt {created_at!r} does not match GetAtt CreatedAt "
        f"{outputs['ASCreatedAt']!r}"
    )
    updated_at = _fmt(as_record["updatedAt"])
    assert updated_at == outputs["ASUpdatedAt"], (
        f"BatchGetAgentSpaces updatedAt {updated_at!r} does not match GetAtt UpdatedAt "
        f"{outputs['ASUpdatedAt']!r}"
    )

    # Independent read at the owning service: SecurityAgent's own record of the artifact, content
    # included.
    got_art = sa.get_artifact(agentSpaceId=as_id, artifactId=artifact_id)
    assert got_art["fileName"] == file_name, f"GetArtifact fileName {got_art['fileName']!r}"
    assert got_art["artifact"]["type"] == "TXT", f"GetArtifact type {got_art['artifact']['type']!r}"
    got_content = base64.b64decode(got_art["artifact"]["contents"])
    assert got_content == payload, f"GetArtifact content {got_content!r}, expected {payload!r}"
    listed_artifacts = _artifact_ids(sa, as_id)
    assert listed_artifacts == [artifact_id], (
        f"ListArtifacts under the space listed {listed_artifacts!r}, expected [{artifact_id!r}]"
    )

    # The Artifact's own delete: drop it from the stack while its agent space stays.
    cf.update_stack(StackName=stack_id, TemplateBody=template(False))
    updated = wait_stack(cf, stack_id)
    assert updated == "UPDATE_COMPLETE", f"expected UPDATE_COMPLETE dropping Art, got {updated!r}"
    still = sa.batch_get_agent_spaces(agentSpaceIds=[as_id])
    assert [s["agentSpaceId"] for s in still["agentSpaces"]] == [as_id], (
        f"the agent space should outlive the artifact's removal: {still!r}"
    )
    remaining = _wait_artifacts_empty(sa, as_id)
    assert remaining == [], f"ListArtifacts after dropping Art listed {remaining!r}"

    delete_stack(cf, stack_id)

    code, message = _wait_agent_space_gone(sa, as_id)
    assert code == "notFound", f"expected the agent space to land in notFound, got {code!r}"
    assert message == as_id, f"expected notFound to carry {as_id!r}, got {message!r}"


def _wait_agent_space_gone(sa, as_id: str, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    deadline = time.monotonic() + timeout_s
    last_found, last_not_found = None, None
    while time.monotonic() < deadline:
        resp = sa.batch_get_agent_spaces(agentSpaceIds=[as_id])
        last_found, last_not_found = resp["agentSpaces"], resp["notFound"]
        if last_found == [] and last_not_found == [as_id]:
            return "notFound", as_id
        time.sleep(interval_s)
    raise AssertionError(
        f"agent space {as_id!r} still resolving after {timeout_s}s of polling "
        f"(agentSpaces={last_found!r}, notFound={last_not_found!r})"
    )


def _wait_artifacts_empty(sa, as_id: str, *, timeout_s: float = 60.0, interval_s: float = 2.0):
    """Poll ListArtifacts under ``as_id`` until it lists nothing; return the last listing."""
    deadline = time.monotonic() + timeout_s
    listed = _artifact_ids(sa, as_id)
    while listed and time.monotonic() < deadline:
        time.sleep(interval_s)
        listed = _artifact_ids(sa, as_id)
    return listed


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
