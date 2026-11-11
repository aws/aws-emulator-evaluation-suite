"""deploy-iottwinmaker-workspace-componenttype-entity-scene-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iottwinmaker-workspace-componenttype-entity-scene-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "iottwinmaker"]

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

_TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [
        {"Effect": "Allow", "Principal": {"Service": "iottwinmaker.amazonaws.com"},
         "Action": "sts:AssumeRole"}
    ],
}


def _workspace_resources(bucket, role_name, ws_id):
    """The workspace's bucket, role and Workspace; the twinmaker types take Tags as a map."""
    return {
        "Bucket": {"Type": "AWS::S3::Bucket",
                   "Properties": {"BucketName": bucket,
                                  "Tags": [{"Key": "sim2real-tm", "Value": ws_id}]}},
        "Role": {
            "Type": "AWS::IAM::Role",
            "Properties": {
                "RoleName": role_name,
                "AssumeRolePolicyDocument": _TRUST_POLICY,
                "Policies": [{
                    "PolicyName": "s3access",
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [{
                            "Effect": "Allow",
                            "Action": ["s3:GetBucket*", "s3:GetObject", "s3:ListBucket",
                                       "s3:PutObject", "s3:DeleteObject"],
                            "Resource": [
                                {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket}"},
                                {"Fn::Sub": f"arn:${{AWS::Partition}}:s3:::{bucket}/*"},
                            ],
                        }],
                    },
                }],
                "Tags": [{"Key": "sim2real-tm", "Value": ws_id}],
            },
        },
        "Workspace": {
            "Type": "AWS::IoTTwinMaker::Workspace",
            "DependsOn": ["Role", "Bucket"],
            "Properties": {
                "WorkspaceId": ws_id,
                "Description": "sim2real twinmaker workspace",
                "Role": {"Fn::GetAtt": ["Role", "Arn"]},
                "S3Location": {"Fn::GetAtt": ["Bucket", "Arn"]},
                "Tags": {"sim2real-tm": ws_id},
            },
        },
    }


def _component_type(ct_id, ws_id, is_stored_externally=True):
    return {
        "Type": "AWS::IoTTwinMaker::ComponentType",
        "DependsOn": ["Workspace"],
        "Properties": {
            "WorkspaceId": {"Ref": "Workspace"},
            "ComponentTypeId": ct_id,
            "PropertyDefinitions": {
                "Temperature": {
                    "DataType": {"Type": "DOUBLE"},
                    "IsTimeSeries": True,
                    "IsStoredExternally": is_stored_externally,
                }
            },
            "Tags": {"sim2real-tm": ws_id},
        },
    }


def _pages(fn, key, **kw):
    """Every item under ``key`` across all nextToken pages of ``fn``."""
    items, token = [], None
    while True:
        page = fn(**kw, **({"nextToken": token} if token else {}))
        items += page.get(key, [])
        token = page.get("nextToken")
        if not token:
            return items


def _own_tags(tm, arn):
    """The resource's own ``sim2real-`` tags (stack-tag propagation is not part of the claim)."""
    tags_map = tm.list_tags_for_resource(resourceARN=arn)["tags"]
    return {k: v for k, v in tags_map.items() if k.startswith("sim2real-")}


def _template(names, with_children=True):
    bucket, role_name, ws_id, ct_id, entity_id, scene_id, entity_name = names
    resources = _workspace_resources(bucket, role_name, ws_id)
    outputs = {
        "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
        "BucketArn": {"Value": {"Fn::GetAtt": ["Bucket", "Arn"]}},
        "WorkspaceRef": {"Value": {"Ref": "Workspace"}},
        "WorkspaceArn": {"Value": {"Fn::GetAtt": ["Workspace", "Arn"]}},
    }
    if with_children:
        resources.update({
            "ComponentType": _component_type(ct_id, ws_id),
            "Entity": {
                "Type": "AWS::IoTTwinMaker::Entity",
                "DependsOn": ["Workspace"],
                "Properties": {
                    "WorkspaceId": {"Ref": "Workspace"},
                    "EntityId": entity_id,
                    "EntityName": entity_name,
                    "Description": "sim2real entity",
                    "Tags": {"sim2real-tm": ws_id},
                },
            },
            "Scene": {
                "Type": "AWS::IoTTwinMaker::Scene",
                "DependsOn": ["Workspace"],
                "Properties": {
                    "WorkspaceId": {"Ref": "Workspace"},
                    "SceneId": scene_id,
                    "ContentLocation": {"Fn::Sub": "s3://${Bucket}/scenes/scene.json"},
                    "Tags": {"sim2real-tm": ws_id},
                },
            },
        })
        outputs.update({
            "ComponentTypeRef": {"Value": {"Ref": "ComponentType"}},
            "ComponentTypeArn": {"Value": {"Fn::GetAtt": ["ComponentType", "Arn"]}},
            "EntityRef": {"Value": {"Ref": "Entity"}},
            "EntityArn": {"Value": {"Fn::GetAtt": ["Entity", "Arn"]}},
            "SceneRef": {"Value": {"Ref": "Scene"}},
            "SceneArn": {"Value": {"Fn::GetAtt": ["Scene", "Arn"]}},
        })
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": resources,
        "Outputs": outputs,
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation IoTTwinMaker Workspace with a ComponentType, Entity and Scene reads back.

    Refs match the listed entries and every templated property and tag reads back; an update
    dropping the three children removes them while the workspace answers, then the stack goes.
    """
    cfn = ctx.client("cloudformation")
    tm = ctx.client("iottwinmaker")
    names = tuple(ctx.unique_name(f"sim2real-tmstk-{k}-")
                  for k in ("b", "role", "ws", "ct", "ent", "sc", "entname"))
    bucket, role_name, ws_id, ct_id, entity_id, scene_id, entity_name = names

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-tmstk-"), _template(names),
                            Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    want_tags = {"sim2real-tm": ws_id}

    # Workspace: Ref against the ListWorkspaces entry; templated properties and tags.
    listed = [w["arn"] for w in _pages(tm.list_workspaces, "workspaceSummaries")
              if w["workspaceId"] == ws_id]
    assert listed == [out["WorkspaceArn"]] and out["WorkspaceRef"] == ws_id, (
        f"ListWorkspaces {listed!r}, Ref {out['WorkspaceRef']!r}, Arn {out['WorkspaceArn']!r}"
    )
    ws = tm.get_workspace(workspaceId=ws_id)
    got = (ws["arn"], ws["role"], ws["s3Location"], ws.get("description"),
           _own_tags(tm, ws["arn"]))
    assert got == (out["WorkspaceArn"], out["RoleArn"], out["BucketArn"],
                   "sim2real twinmaker workspace", want_tags), f"workspace {got!r}"

    # Children: each Ref is WorkspaceId|Id of the entry IoTTwinMaker lists in the workspace.
    cts = [c["arn"] for c in _pages(tm.list_component_types, "componentTypeSummaries",
                                    workspaceId=ws_id) if c["componentTypeId"] == ct_id]
    assert (cts, out["ComponentTypeRef"]) == ([out["ComponentTypeArn"]], f"{ws_id}|{ct_id}"), (
        f"ListComponentTypes {cts!r}, Ref {out['ComponentTypeRef']!r}"
    )
    ct = tm.get_component_type(workspaceId=ws_id, componentTypeId=ct_id)
    temperature = ct["propertyDefinitions"]["Temperature"]
    got = (ct["status"]["state"], temperature["dataType"]["type"], temperature["isTimeSeries"],
           temperature["isStoredExternally"], _own_tags(tm, ct["arn"]))
    assert got == ("ACTIVE", "DOUBLE", True, True, want_tags), f"component type {got!r}"

    entities = [e["arn"] for e in _pages(tm.list_entities, "entitySummaries", workspaceId=ws_id)
                if e["entityId"] == entity_id]
    assert (entities, out["EntityRef"]) == ([out["EntityArn"]], f"{ws_id}|{entity_id}"), (
        f"ListEntities {entities!r}, Ref {out['EntityRef']!r}"
    )
    entity = tm.get_entity(workspaceId=ws_id, entityId=entity_id)
    got = (entity["status"]["state"], entity["entityName"], entity.get("description"),
           _own_tags(tm, entity["arn"]))
    assert got == ("ACTIVE", entity_name, "sim2real entity", want_tags), f"entity {got!r}"

    scenes = [s["arn"] for s in _pages(tm.list_scenes, "sceneSummaries", workspaceId=ws_id)
              if s["sceneId"] == scene_id]
    assert (scenes, out["SceneRef"]) == ([out["SceneArn"]], f"{ws_id}|{scene_id}"), (
        f"ListScenes {scenes!r}, Ref {out['SceneRef']!r}"
    )
    scene = tm.get_scene(workspaceId=ws_id, sceneId=scene_id)
    got = (scene["contentLocation"], _own_tags(tm, scene["arn"]))
    assert got == (f"s3://{bucket}/scenes/scene.json", want_tags), f"scene {got!r}"

    # Children before parent: the update drops all three while the workspace still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(names, with_children=False),
                     Capabilities=["CAPABILITY_NAMED_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"
    assert tm.get_workspace(workspaceId=ws_id)["arn"] == out["WorkspaceArn"], "workspace gone"
    ct_gone = ("ResourceNotFoundException", f"Cannot find component type {ct_id} in workspace "
               f"{ws_id}.")
    expect_error(lambda: tm.get_component_type(workspaceId=ws_id, componentTypeId=ct_id),
                 *ct_gone)
    entity_gone = ("ResourceNotFoundException", f"Entity {entity_id} in workspace {ws_id} not found.")
    expect_error(lambda: tm.get_entity(workspaceId=ws_id, entityId=entity_id), *entity_gone)
    scene_gone = ("ResourceNotFoundException", f"Scene: {scene_id} cannot be found in workspace "
                  f"{ws_id}")
    expect_error(lambda: tm.get_scene(workspaceId=ws_id, sceneId=scene_id), *scene_gone)

    delete_stack(cfn, stack_id)
    ws_gone = ("ResourceNotFoundException", f"Unable to find workspace for id: {ws_id}")
    expect_error(lambda: tm.get_workspace(workspaceId=ws_id), *ws_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
