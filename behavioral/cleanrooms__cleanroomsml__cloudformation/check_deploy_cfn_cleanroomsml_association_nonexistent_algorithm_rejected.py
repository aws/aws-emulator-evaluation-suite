"""deploy-cfn-cleanroomsml-association-nonexistent-algorithm-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-cfn-cleanroomsml-association-nonexistent-algorithm-rejected"
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
_HANDLER_REASON = re.compile(
    r'^Resource handler returned message: "(?P<message>.*)" '
    r"\(RequestToken: [0-9a-f-]+, HandlerErrorCode: (?P<code>[A-Za-z]+)\)$",
    re.DOTALL,
)


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


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


def handler_reason(reason, account, *names):
    """``(masked message, HandlerErrorCode)`` of a registry-handler reason; compare with ==."""
    m = _HANDLER_REASON.match(reason or "")
    assert m is not None, f"not a resource-handler failure reason: {reason!r}"
    return masked(m["message"], account, *names), m["code"]


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
_MISSING_ID = "00000000000000000000000000000000"
# A well-formed ARN of this account's algorithm that does not exist: the one bad value.
_MISSING = {"Fn::Sub": "arn:${AWS::Partition}:cleanrooms-ml:${AWS::Region}:${AWS::AccountId}:"
                       f"configured-model-algorithm/{_MISSING_ID}"}
_REAL = {"Ref": "Algorithm"}


def _template(region, names, algorithm_arn):
    registry = _XGBOOST_REGISTRY[region]
    return json.dumps({
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
                "Name": names["algo"],
                "RoleArn": {"Fn::GetAtt": ["Role", "Arn"]},
                "TrainingContainerConfig": {"ImageUri": f"{registry}.dkr.ecr.{region}.amazonaws.com"
                                                        "/sagemaker-xgboost:1.5-1"},
            }},
            "Collab": {"Type": "AWS::CleanRooms::Collaboration", "Properties": {
                "Name": names["collab"],
                "Description": "fidelity check collaboration",
                "CreatorDisplayName": "creator",
                "QueryLogStatus": "DISABLED",
                "CreatorMemberAbilities": ["CAN_QUERY", "CAN_RECEIVE_RESULTS"],
                "CreatorMLMemberAbilities": {"CustomMLMemberAbilities": ["CAN_RECEIVE_MODEL_OUTPUT"]},
                "Members": [],
            }},
            "Membership": {
                "Type": "AWS::CleanRooms::Membership",
                # The creator's own ACTIVE membership cannot be deleted; it is retained (on a
                # rollback too) and leaves ListMemberships with its deleted collaboration.
                "DeletionPolicy": "Retain",
                "Properties": {"CollaborationIdentifier": {"Ref": "Collab"},
                               "QueryLogStatus": "DISABLED"},
            },
            "Association": {
                "Type": "AWS::CleanRoomsML::ConfiguredModelAlgorithmAssociation",
                "Properties": {
                    "MembershipIdentifier": {"Ref": "Membership"},
                    "ConfiguredModelAlgorithmArn": algorithm_arn,
                    "Name": names["assoc"],
                },
            },
        },
        "Outputs": {
            "AlgoArn": {"Value": {"Ref": "Algorithm"}},
            "AssocArn": {"Value": {"Ref": "Association"}},
            "MembershipId": {"Value": {"Ref": "Membership"}},
        },
    })


def _active_collabs(cr, name):
    return [c for c in paginate(cr, "list_collaborations", "collaborationList", memberStatus="ACTIVE")
            if c["name"] == name]


def _drop_collaboration(cr, cf, stack_id, name):
    """Delete the stack, then any collaboration of ``name`` it left behind (the retained member)."""
    delete_stack(cf, stack_id)
    for collab in _active_collabs(cr, name):
        cr.delete_collaboration(collaborationIdentifier=collab["id"])


def _names(ctx, tag):
    return {k: ctx.unique_name(f"sim2real-crmlr-{tag}-{k}-") for k in ("algo", "collab", "assoc")}


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Association naming a nonexistent ConfiguredModelAlgorithm ARN is refused.

    The stack rolls back with CleanRoomsML's exact NotFound; the collaboration is gone and no
    membership of it is listed, while the same template naming the real algorithm deploys.
    """
    cfn = ctx.client("cloudformation")
    cr = ctx.client("cleanrooms")
    crml = ctx.client("cleanroomsml")
    assert ctx.region in _XGBOOST_REGISTRY, f"precondition: no XGBoost registry for {ctx.region}"
    good, bad = _names(ctx, "good"), _names(ctx, "bad")

    # Positive control: the same template, the association naming the stack's real algorithm.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-crmlr-good-"),
                           _template(ctx.region, good, _REAL), Capabilities=["CAPABILITY_IAM"])
    ctx.on_cleanup(lambda: _drop_collaboration(cr, cfn, good_id, good["collab"]))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    out = stack_outputs(cfn, good_id)
    assoc = crml.get_configured_model_algorithm_association(
        configuredModelAlgorithmAssociationArn=out["AssocArn"],
        membershipIdentifier=out["MembershipId"])
    got = (assoc["name"], assoc["configuredModelAlgorithmArn"])
    assert got == (good["assoc"], out["AlgoArn"]), f"control association {got!r}"

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-crmlr-bad-"),
                          _template(ctx.region, bad, _MISSING), Capabilities=["CAPABILITY_IAM"])
    ctx.on_cleanup(lambda: _drop_collaboration(cr, cfn, bad_id, bad["collab"]))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    partition = bad_id.split(":")[1]
    missing = (f"arn:{partition}:cleanrooms-ml:{ctx.region}:<account>:configured-model-algorithm/"
               f"{_MISSING_ID}")
    want = (f"Configured Model Algorithm: {missing} not found. (Service: CleanRoomsMl, Status "
            "Code: 404, Request ID: <id>) (SDK Attempt Count: <n>)", "NotFound")
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Association"), ctx.account,
                         *bad.values())
    assert got == want, f"handler reason {got!r}, expected {want!r}"

    # Rollback outcome through CleanRooms, before any delete: the collaboration is gone (the
    # control's is listed) and ListMemberships lists no membership of the deleted collaboration.
    assert _active_collabs(cr, good["collab"]) != [], "the control collaboration is not listed"
    left = _active_collabs(cr, bad["collab"])
    assert left == [], f"the rolled-back collaboration is listed: {left!r}"
    memberships = paginate(cr, "list_memberships", "membershipSummaries")
    listed = {name: [m["status"] for m in memberships if m["collaborationName"] == name]
              for name in (good["collab"], bad["collab"])}
    assert listed == {good["collab"]: ["ACTIVE"], bad["collab"]: []}, (
        f"memberships of the control and the rolled-back collaboration: {listed!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
