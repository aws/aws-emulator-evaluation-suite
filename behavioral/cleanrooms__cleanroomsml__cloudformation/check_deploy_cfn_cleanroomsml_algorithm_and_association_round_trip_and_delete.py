"""deploy-cfn-cleanroomsml-algorithm-and-association-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-cleanroomsml-algorithm-and-association-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cleanrooms", "cleanroomsml", "cloudformation"]

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

# external-identity: a ConfiguredModelAlgorithm must reference a real, readable container image;
# these are the published AWS-owned SageMaker built-in XGBoost registries, one per region.
_XGBOOST_REGISTRY = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "ap-northeast-1": "354813040037",
    "ap-northeast-2": "366743142698",
    "ap-south-1": "720646828776",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ca-central-1": "341280168497",
    "eu-central-1": "492215442770",
    "eu-north-1": "662702820516",
    "eu-west-1": "141502667606",
    "eu-west-2": "764974769150",
    "eu-west-3": "659782779980",
    "sa-east-1": "737474898029",
}
_DESCRIPTION = "fidelity check collaboration"


def _image(region):
    assert region in _XGBOOST_REGISTRY, f"precondition: no SageMaker XGBoost registry for {region}"
    return f"{_XGBOOST_REGISTRY[region]}.dkr.ecr.{region}.amazonaws.com/sagemaker-xgboost:1.5-1"


def _template(region, algo_name, collab_name, assoc_name, with_association=True):
    registry = _XGBOOST_REGISTRY[region]
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Role": {"Type": "AWS::IAM::Role", "Properties": {
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": [{
                    "Effect": "Allow", "Principal": {"Service": "cleanrooms-ml.amazonaws.com"},
                    "Action": "sts:AssumeRole"}]},
                "Policies": [{"PolicyName": "ecr-pull", "PolicyDocument": {
                    "Version": "2012-10-17", "Statement": [{
                        "Effect": "Allow",
                        "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer",
                                   "ecr:BatchCheckLayerAvailability"],
                        "Resource": {"Fn::Sub": "arn:${AWS::Partition}:ecr:${AWS::Region}:"
                                                f"{registry}:repository/sagemaker-xgboost"},
                    }]}}],
            }},
            "Algorithm": {"Type": "AWS::CleanRoomsML::ConfiguredModelAlgorithm", "Properties": {
                "Name": algo_name,
                "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                "TrainingContainerConfig": {"ImageUri": _image(region)},
            }},
            "Collab": {"Type": "AWS::CleanRooms::Collaboration", "Properties": {
                "Name": collab_name,
                "Description": _DESCRIPTION,
                "CreatorDisplayName": "creator",
                "QueryLogStatus": "DISABLED",
                "CreatorMemberAbilities": ["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
                "CreatorMLMemberAbilities": {"CustomMLMemberAbilities": ["CAN_RECEIVE_MODEL_OUTPUT"]},
                "Members": [],
            }},
            "Membership": {
                "Type": "AWS::CleanRooms::Membership",
                # The creator's own ACTIVE membership cannot be deleted; retaining it lets the
                # stack delete the collaboration, which tombstones it as COLLABORATION_DELETED.
                "DeletionPolicy": "Retain",
                "Properties": {"CollaborationIdentifier": {"Ref": "Collab"},
                               "QueryLogStatus": "DISABLED"},
            },
            "Association": {
                "Type": "AWS::CleanRoomsML::ConfiguredModelAlgorithmAssociation",
                "Properties": {
                    "MembershipIdentifier": {"Ref": "Membership"},
                    "ConfiguredModelAlgorithmArn": {"Ref": "Algorithm"},
                    "Name": assoc_name,
                },
            },
        },
        "Outputs": {
            "AlgoArn": {"Value": {"Ref": "Algorithm"}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["Role", "Arn"]}},
            "CollabId": {"Value": {"Ref": "Collab"}},
            "MembershipId": {"Value": {"Ref": "Membership"}},
            "AssocArn": {"Value": {"Ref": "Association"}},
            "AssocCollabId": {"Value": {"Fn::GetAtt": ["Association", "CollaborationIdentifier"]}},
        },
    }
    if not with_association:
        del template["Resources"]["Association"]
        del template["Outputs"]["AssocArn"], template["Outputs"]["AssocCollabId"]
    return json.dumps(template)


def _active_collabs(cr, name):
    return [c for c in paginate(cr, "list_collaborations", "collaborationList", memberStatus="ACTIVE")
            if c["name"] == name]


def _drop_collaboration(cr, cf, stack_id, name):
    """Delete the stack, then any collaboration of ``name`` it left behind (the retained member)."""
    delete_stack(cf, stack_id)
    for collab in _active_collabs(cr, name):
        cr.delete_collaboration(collaborationIdentifier=collab["id"])


@tags("axis:happy-path", "cap:c3", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation ConfiguredModelAlgorithm and Association on a one-member collaboration read back.

    Every Ref and templated property matches CleanRooms reads; dropping the association removes it
    while the algorithm answers; the stack delete removes the rest, tombstoning the membership.
    """
    cfn = ctx.client("cloudformation")
    crml = ctx.client("cleanroomsml")
    cr = ctx.client("cleanrooms")
    algo_name = ctx.unique_name("sim2real-crmla-algo-")
    collab_name = ctx.unique_name("sim2real-crmla-collab-")
    assoc_name = ctx.unique_name("sim2real-crmla-assoc-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-crmla-"),
                            _template(ctx.region, algo_name, collab_name, assoc_name),
                            Capabilities=["CAPABILITY_IAM"])
    ctx.on_cleanup(lambda: _drop_collaboration(cr, cfn, stack_id, collab_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    algo_arn, collab_id, membership_id = out["AlgoArn"], out["CollabId"], out["MembershipId"]

    # Collaboration: Ref against the list entry by name, then every templated property.
    listed = [c["id"] for c in _active_collabs(cr, collab_name)]
    assert listed == [collab_id], f"ListCollaborations named {collab_name!r}: {listed!r}"
    collab = cr.get_collaboration(collaborationIdentifier=collab_id)["collaboration"]
    got = (collab["id"], collab["name"], collab["description"], collab["creatorDisplayName"],
           collab["queryLogStatus"], collab["creatorAccountId"])
    want = (collab_id, collab_name, _DESCRIPTION, "creator", "DISABLED", ctx.account)
    assert got == want, f"GetCollaboration {got!r}, expected {want!r}"

    # Membership: Ref against the list entry of this collaboration.
    members = [m for m in paginate(cr, "list_memberships", "membershipSummaries")
               if m["collaborationId"] == collab_id]
    assert [m["id"] for m in members] == [membership_id], f"ListMemberships {members!r}"
    membership = cr.get_membership(membershipIdentifier=membership_id)["membership"]
    got = (membership["status"], membership["queryLogStatus"], sorted(membership["memberAbilities"]),
           membership["mlMemberAbilities"])
    want = ("ACTIVE", "DISABLED", ["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
            {"customMLMemberAbilities": ["CAN_RECEIVE_MODEL_OUTPUT"]})
    assert got == want, f"GetMembership {got!r}, expected {want!r}"

    # Algorithm: Ref against the list entry by name, then every templated property.
    algos = [a["configuredModelAlgorithmArn"]
             for a in paginate(crml, "list_configured_model_algorithms", "configuredModelAlgorithms")
             if a["name"] == algo_name]
    assert algos == [algo_arn], f"ListConfiguredModelAlgorithms named {algo_name!r}: {algos!r}"
    algo = crml.get_configured_model_algorithm(configuredModelAlgorithmArn=algo_arn)
    got = (algo["name"], algo["roleArn"], algo["trainingContainerConfig"]["imageUri"])
    want = (algo_name, out["RoleArn"], _image(ctx.region))
    assert got == want, f"GetConfiguredModelAlgorithm {got!r}, expected {want!r}"

    # Association: Ref and the CollaborationIdentifier GetAtt against the membership's list.
    assocs = paginate(crml, "list_configured_model_algorithm_associations",
                      "configuredModelAlgorithmAssociations", membershipIdentifier=membership_id)
    got = [(a["configuredModelAlgorithmAssociationArn"], a["name"], a["configuredModelAlgorithmArn"],
            a["collaborationIdentifier"]) for a in assocs]
    want = [(out["AssocArn"], assoc_name, algo_arn, out["AssocCollabId"])]
    assert got == want and out["AssocCollabId"] == collab_id, (
        f"ListConfiguredModelAlgorithmAssociations {got!r}, expected {want!r}"
    )
    assoc_arn = out["AssocArn"]

    # Child first: the update drops only the association; its own NotFound while the same
    # algorithm (createTime) and the membership still answer.
    cfn.update_stack(StackName=stack_id, Capabilities=["CAPABILITY_IAM"], TemplateBody=_template(
        ctx.region, algo_name, collab_name, assoc_name, with_association=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"association-dropping update ended {status!r}"
    configured_model_algorithm_association_gone = (
        "ResourceNotFoundException",
        f"Configured Model Algorithm Association: {assoc_arn} not found.",
    )
    expect_error(
        lambda: crml.get_configured_model_algorithm_association(
            configuredModelAlgorithmAssociationArn=assoc_arn, membershipIdentifier=membership_id),
        *configured_model_algorithm_association_gone,
    )
    kept = crml.get_configured_model_algorithm(configuredModelAlgorithmArn=algo_arn)
    assert kept["createTime"] == algo["createTime"], (
        f"algorithm createTime {kept['createTime']!r} after the update, was {algo['createTime']!r}"
    )
    kept_status = cr.get_membership(membershipIdentifier=membership_id)["membership"]["status"]
    assert kept_status == "ACTIVE", f"membership status after the update {kept_status!r}"

    delete_stack(cfn, stack_id)
    configured_model_algorithm_gone = (
        "ResourceNotFoundException",
        f"Configured Model Algorithm: {algo_arn} not found.",
    )
    expect_error(lambda: crml.get_configured_model_algorithm(configuredModelAlgorithmArn=algo_arn),
                 *configured_model_algorithm_gone)
    left = _active_collabs(cr, collab_name)
    assert left == [], f"the deleted collaboration is still listed: {left!r}"
    tombstone = cr.get_membership(membershipIdentifier=membership_id)["membership"]["status"]
    assert tombstone == "COLLABORATION_DELETED", f"retained membership status {tombstone!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
