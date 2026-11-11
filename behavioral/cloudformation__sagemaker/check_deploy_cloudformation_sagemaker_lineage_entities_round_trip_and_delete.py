"""deploy-cloudformation-sagemaker-lineage-entities-round-trip-and-delete."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-sagemaker-lineage-entities-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "sagemaker"]

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

def _parse_getatt_time(value: str) -> datetime.datetime:
    return datetime.datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(
        tzinfo=datetime.timezone.utc
    )


def _template(action_name, artifact_type, context_name, source_uri_prefix,
               action_description, context_description):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Act": {
                "Type": "AWS::SageMaker::Action",
                "Properties": {
                    "ActionName": action_name,
                    "ActionType": "ModelDeployment",
                    "Source": {"SourceUri": f"{source_uri_prefix}/action"},
                    "Description": action_description,
                    "Tags": [{"Key": "sim2real-lineage", "Value": "action"}],
                },
            },
            "Art": {
                "Type": "AWS::SageMaker::Artifact",
                "Properties": {
                    "ArtifactType": artifact_type,
                    "Source": {"SourceUri": f"{source_uri_prefix}/artifact"},
                    "Tags": [{"Key": "sim2real-lineage", "Value": "artifact"}],
                },
            },
            "Ctx": {
                "Type": "AWS::SageMaker::Context",
                "Properties": {
                    "ContextName": context_name,
                    "ContextType": "Endpoint",
                    "Source": {"SourceUri": f"{source_uri_prefix}/context"},
                    "Description": context_description,
                    "Tags": [{"Key": "sim2real-lineage", "Value": "context"}],
                },
            },
        },
        "Outputs": {
            "ActionArn": {"Value": {"Ref": "Act"}},
            "ActionCreationTime": {"Value": {"Fn::GetAtt": ["Act", "CreationTime"]}},
            "ArtifactArn": {"Value": {"Ref": "Art"}},
            "ArtifactCreationTime": {"Value": {"Fn::GetAtt": ["Art", "CreationTime"]}},
            "ContextArn": {"Value": {"Ref": "Ctx"}},
            "ContextCreationTime": {"Value": {"Fn::GetAtt": ["Ctx", "CreationTime"]}},
        },
    })


def _tags(sm, arn):
    return {t["Key"]: t["Value"] for t in paginate(sm, "list_tags", "Tags", ResourceArn=arn)
            if not t["Key"].startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """CloudFormation-provisioned AWS::SageMaker::Action, ::Artifact and ::Context each reach
    SageMaker with the declared type, source, description, tags and Ref/GetAtt values; deleting
    the stack removes all three from SageMaker.
    """
    cfn = ctx.client("cloudformation")
    sm = ctx.client("sagemaker")
    stack = ctx.unique_name("sim2real-cfn-lineage-")
    action_name = ctx.unique_name("sim2real-lineage-action-")
    context_name = ctx.unique_name("sim2real-lineage-context-")
    artifact_type = ctx.unique_name("sim2real-artifacttype-")
    source_uri_prefix = f"s3://{ctx.unique_name('sim2real-lineage-bucket-')}"
    action_description = ctx.unique_name("sim2real-action-desc-")
    context_description = ctx.unique_name("sim2real-context-desc-")

    stack_id = create_stack(
        ctx, cfn, stack,
        _template(action_name, artifact_type, context_name, source_uri_prefix,
                  action_description, context_description),
    )
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]
    prefix = f"arn:{partition}:sagemaker:{ctx.region}:{ctx.account}"
    action_arn = f"{prefix}:action/{action_name}"
    context_arn = f"{prefix}:context/{context_name}"

    action = sm.describe_action(ActionName=action_name)
    got = (outputs["ActionArn"], action["ActionArn"], action.get("ActionType"),
           action["Source"].get("SourceUri"), action.get("Description"))
    want = (action_arn, action_arn, "ModelDeployment", f"{source_uri_prefix}/action",
            action_description)
    assert got == want, f"action (Ref, Arn, Type, SourceUri, Description) {got!r} != {want!r}"
    assert action["CreationTime"] == _parse_getatt_time(outputs["ActionCreationTime"]), (
        f"GetAtt CreationTime {outputs['ActionCreationTime']!r} != DescribeAction CreationTime "
        f"{action['CreationTime']!r}"
    )
    got = _tags(sm, action_arn)
    assert got == {"sim2real": stack, "sim2real-lineage": "action"}, f"action tags {got!r}"

    # The artifact's ARN is minted by SageMaker: Ref == the one entry listed for its source URI.
    artifact_arn = outputs["ArtifactArn"]
    listed = [a["ArtifactArn"] for a in paginate(
        sm, "list_artifacts", "ArtifactSummaries", SourceUri=f"{source_uri_prefix}/artifact")]
    assert listed == [artifact_arn], f"ListArtifacts {listed!r} for Ref {artifact_arn!r}"
    artifact = sm.describe_artifact(ArtifactArn=artifact_arn)
    got = (artifact.get("ArtifactType"), artifact["Source"].get("SourceUri"))
    assert got == (artifact_type, f"{source_uri_prefix}/artifact"), f"artifact reads {got!r}"
    assert artifact["CreationTime"] == _parse_getatt_time(outputs["ArtifactCreationTime"]), (
        f"GetAtt CreationTime {outputs['ArtifactCreationTime']!r} != DescribeArtifact CreationTime "
        f"{artifact['CreationTime']!r}"
    )
    got = _tags(sm, artifact_arn)
    assert got == {"sim2real": stack, "sim2real-lineage": "artifact"}, f"artifact tags {got!r}"

    context = sm.describe_context(ContextName=context_name)
    got = (outputs["ContextArn"], context["ContextArn"], context.get("ContextType"),
           context["Source"].get("SourceUri"), context.get("Description"))
    want = (context_arn, context_arn, "Endpoint", f"{source_uri_prefix}/context",
            context_description)
    assert got == want, f"context (Ref, Arn, Type, SourceUri, Description) {got!r} != {want!r}"
    assert context["CreationTime"] == _parse_getatt_time(outputs["ContextCreationTime"]), (
        f"GetAtt CreationTime {outputs['ContextCreationTime']!r} != DescribeContext CreationTime "
        f"{context['CreationTime']!r}"
    )
    got = _tags(sm, context_arn)
    assert got == {"sim2real": stack, "sim2real-lineage": "context"}, f"context tags {got!r}"

    delete_stack(cfn, stack_id)
    gone = ("ResourceNotFound", f"Action '{action_arn}' does not exist.")
    expect_error(lambda: sm.describe_action(ActionName=action_name), *gone)
    gone = ("ResourceNotFound", f"Artifact '{artifact_arn}' does not exist.")
    expect_error(lambda: sm.describe_artifact(ArtifactArn=artifact_arn), *gone)
    gone = ("ResourceNotFound", f"Context '{context_arn}' does not exist.")
    expect_error(lambda: sm.describe_context(ContextName=context_name), *gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
