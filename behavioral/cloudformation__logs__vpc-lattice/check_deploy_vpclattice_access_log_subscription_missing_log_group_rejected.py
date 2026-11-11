"""deploy-vpclattice-access-log-subscription-missing-log-group-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-vpclattice-access-log-subscription-missing-log-group-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "logs", "vpc-lattice"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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


def _template(sn_name: str, log_group_name: str, missing_log_group_name: str | None) -> str:
    """The network, a real log group and a subscription; only its DestinationArn varies."""
    if missing_log_group_name is None:
        destination = {"Fn::GetAtt": ["Lg", "Arn"]}
    else:
        destination = {"Fn::Sub": (
            "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:"
            f"{missing_log_group_name}"
        )}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Sn": {"Type": "AWS::VpcLattice::ServiceNetwork",
                   "Properties": {"Name": sn_name,
                                  "Tags": [{"Key": "sim2real-sn", "Value": sn_name}]}},
            "Lg": {"Type": "AWS::Logs::LogGroup",
                   "Properties": {"LogGroupName": log_group_name, "RetentionInDays": 1}},
            "Als": {"Type": "AWS::VpcLattice::AccessLogSubscription",
                    "Properties": {"ResourceIdentifier": {"Ref": "Sn"},
                                   "DestinationArn": destination}},
        },
        "Outputs": {
            "SnArn": {"Value": {"Ref": "Sn"}},
            "AlsArn": {"Value": {"Ref": "Als"}},
        },
    })


def _networks(vl, name):
    return [n for n in paginate(vl, "list_service_networks", "items") if n["name"] == name]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::VpcLattice::AccessLogSubscription whose DestinationArn names a log
    group that does not exist is refused with VPC Lattice's exact NotFound and its network rolls
    back, while the same template pointing at its real log group deploys.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-vpclattice-accesslogsubscription.html
    """
    vl = ctx.client("vpc-lattice")
    logs = ctx.client("logs")
    cfn = ctx.client("cloudformation")
    bad_sn_name = ctx.unique_name("sim2real-vpclattice-snbad-")
    bad_lg_name = ctx.unique_name("/sim2real/vpclattice-bad-")
    missing_lg_name = ctx.unique_name("/sim2real/vpclattice-missing-")

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-vpclattice-alsbad-stack-"),
                          _template(bad_sn_name, bad_lg_name, missing_lg_name))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cfn, bad_id)
    assert rows == [], f"refused by early validation, not by the handler: {rows!r}"
    partition = bad_id.split(":")[1]
    dest_arn = f"arn:{partition}:logs:{ctx.region}:<account>:log-group:{missing_lg_name}"
    want = (
        f"AccessLogSubscription destination {dest_arn} cannot be found. "
        "(Service: VpcLattice, Status Code: 404, Request ID: <id>) (SDK Attempt Count: <n>)",
        "NotFound",
    )
    reason = failed_reason(stack_events(cfn, bad_id), "Als")
    got = handler_reason(reason, ctx.account)
    assert got == want, f"handler reason {got!r}, expected {want!r}"

    # Rollback absence through VPC Lattice and Logs, by name, before this check deletes anything.
    assert _networks(vl, bad_sn_name) == [], f"the rolled-back network {bad_sn_name!r} is listed"
    left = [g for g in paginate(logs, "describe_log_groups", "logGroups",
                                logGroupNamePrefix=bad_lg_name) if g["logGroupName"] == bad_lg_name]
    assert left == [], f"the rolled-back log group {bad_lg_name!r} is listed"

    # Positive control: the same template, DestinationArn naming its real log group.
    good_sn_name = ctx.unique_name("sim2real-vpclattice-sngood-")
    good_lg_name = ctx.unique_name("/sim2real/vpclattice-good-")
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-vpclattice-alsgood-stack-"),
                           _template(good_sn_name, good_lg_name, None))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", (
        f"control stack ended {status!r}: {decisive_rows(stack_events(cfn, good_id))!r}"
    )
    out = stack_outputs(cfn, good_id)
    networks = _networks(vl, good_sn_name)
    assert [n["arn"] for n in networks] == [out["SnArn"]], (
        f"ListServiceNetworks entries named {good_sn_name!r}: {networks!r}, Ref {out['SnArn']!r}"
    )
    subs = paginate(vl, "list_access_log_subscriptions", "items",
                    resourceIdentifier=networks[0]["id"])
    want_dest = f"arn:{partition}:logs:{ctx.region}:{ctx.account}:log-group:{good_lg_name}:*"
    got = [(s["arn"], s["destinationArn"]) for s in subs]
    assert got == [(out["AlsArn"], want_dest)], (
        f"control subscriptions {got!r}, expected [({out['AlsArn']!r}, {want_dest!r})]"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
