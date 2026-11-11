"""deploy-gameliftstreams-stream-group-round-trip-and-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-gameliftstreams-stream-group-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "gameliftstreams"]

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

_INTERNAL_ID_RE = re.compile(r"\(Internal ID: [0-9a-f-]+\)")


def _template(description: str, location_name: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Sg": {
                "Type": "AWS::GameLiftStreams::StreamGroup",
                "Properties": {
                    "Description": description,
                    "StreamClass": "gen4n_win2022",
                    "LocationConfigurations": [
                        {"LocationName": location_name, "AlwaysOnCapacity": 0,
                         "OnDemandCapacity": 0},
                    ],
                    "Tags": {"sim2real-gls": description},
                },
            },
        },
        "Outputs": {
            "SgArn": {"Value": {"Ref": "Sg"}},
            "SgId": {"Value": {"Fn::GetAtt": ["Sg", "Id"]}},
        },
    })


def _not_found(fn) -> tuple[str, str]:
    """(code, message with the Internal ID masked) of the ClientError ``fn()`` raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), _INTERNAL_ID_RE.sub("(Internal ID: <id>)", err.get("Message", ""))
    raise AssertionError(f"expected NotFound but the call succeeded: {result!r}")


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::GameLiftStreams::StreamGroup reads back and is removed with its stack.

    Ref and the Id GetAtt match the group GameLiftStreams lists, every templated property and tag
    reads back on an ACTIVE group, and after the delete GetStreamGroup answers NotFound.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-gameliftstreams-streamgroup.html
    """
    cfn = ctx.client("cloudformation")
    gls = ctx.client("gameliftstreams")
    stack = ctx.unique_name("sim2real-glsstack-")
    description = ctx.unique_name("sim2real-glssg-")

    stack_id = create_stack(ctx, cfn, stack, _template(description, ctx.region))
    status = wait_stack(cfn, stack_id, timeout_s=600.0)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]

    # Ref and the read-only GetAtt Id against an independent read: the listed group, every page.
    listed = [(g["Arn"], g["Id"]) for g in paginate(gls, "list_stream_groups", "Items")
              if g.get("Description") == description]
    assert listed == [(outputs["SgArn"], outputs["SgId"])], (
        f"ListStreamGroups found {listed!r}; Ref/GetAtt are {outputs!r}"
    )
    sg_arn, sg_id = listed[0]
    want_arn = f"arn:{partition}:gameliftstreams:{ctx.region}:{ctx.account}:streamgroup/{sg_id}"
    assert sg_arn == want_arn, f"Ref {sg_arn!r}, expected {want_arn!r}"

    group = gls.get_stream_group(Identifier=sg_arn)
    got = {
        "Arn": group["Arn"], "Id": group["Id"], "Description": group["Description"],
        "StreamClass": group["StreamClass"], "Status": group["Status"],
        "LocationStates": [(loc["LocationName"], loc["Status"], loc["AlwaysOnCapacity"],
                            loc["OnDemandCapacity"]) for loc in group["LocationStates"]],
    }
    want = {
        "Arn": sg_arn, "Id": sg_id, "Description": description, "StreamClass": "gen4n_win2022",
        "Status": "ACTIVE", "LocationStates": [(ctx.region, "ACTIVE", 0, 0)],
    }
    assert got == want, f"GetStreamGroup reads {got!r}, expected {want!r}"
    group_tags = gls.list_tags_for_resource(ResourceArn=sg_arn).get("Tags", {})
    own = {k: v for k, v in group_tags.items() if k != "sim2real" and not k.startswith("aws:")}
    assert own == {"sim2real-gls": description}, f"stream group tags {group_tags!r}"

    delete_stack(cfn, stack_id)
    got = _not_found(lambda: gls.get_stream_group(Identifier=sg_arn))
    want = ("ResourceNotFoundException", f"Resource '{sg_arn}' does not exist (Internal ID: <id>)")
    assert got == want, f"after the delete GetStreamGroup raised {got!r}, expected {want!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
