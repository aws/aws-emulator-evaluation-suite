"""deploy-vpclattice-access-log-subscription-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-vpclattice-access-log-subscription-round-trip-and-delete"
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

_RETENTION_DAYS = 1


def _template(sn_name: str, log_group_name: str, with_subscription: bool = True) -> str:
    resources = {
        "Sn": {"Type": "AWS::VpcLattice::ServiceNetwork",
               "Properties": {"Name": sn_name,
                              "Tags": [{"Key": "sim2real-sn", "Value": sn_name}]}},
        "Lg": {"Type": "AWS::Logs::LogGroup",
               "Properties": {"LogGroupName": log_group_name,
                              "RetentionInDays": _RETENTION_DAYS,
                              "Tags": [{"Key": "sim2real-lg", "Value": log_group_name}]}},
    }
    outputs = {
        "SnArn": {"Value": {"Ref": "Sn"}},
        "SnId": {"Value": {"Fn::GetAtt": ["Sn", "Id"]}},
        "LgArn": {"Value": {"Fn::GetAtt": ["Lg", "Arn"]}},
    }
    if with_subscription:
        resources["Als"] = {
            "Type": "AWS::VpcLattice::AccessLogSubscription",
            "Properties": {"ResourceIdentifier": {"Ref": "Sn"},
                           "DestinationArn": {"Fn::GetAtt": ["Lg", "Arn"]},
                           "Tags": [{"Key": "sim2real-als", "Value": sn_name}]},
        }
        outputs["AlsArn"] = {"Value": {"Ref": "Als"}}
        outputs["AlsId"] = {"Value": {"Fn::GetAtt": ["Als", "Id"]}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


def _own_tags(tags_):
    """A resource's tags without CloudFormation's aws:* system tags."""
    return {k: v for k, v in tags_.items() if not k.startswith("aws:")}


def _groups(logs, name):
    return [g for g in paginate(logs, "describe_log_groups", "logGroups", logGroupNamePrefix=name)
            if g["logGroupName"] == name]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::VpcLattice::AccessLogSubscription to a log group reads back through
    VPC Lattice with the declared network, destination and tags; an update dropping it removes
    it while the network answers, and the stack delete removes the network and the log group.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-vpclattice-accesslogsubscription.html
    """
    vl = ctx.client("vpc-lattice")
    logs = ctx.client("logs")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-vpclattice-als-stack-")
    sn_name = ctx.unique_name("sim2real-vpclattice-sn-")
    log_group_name = ctx.unique_name("/sim2real/vpclattice-")

    stack_id = create_stack(ctx, cfn, stack, _template(sn_name, log_group_name))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    partition = stack_id.split(":")[1]

    # Refs against independent lists: the network by name, the subscription under the network.
    networks = [n for n in paginate(vl, "list_service_networks", "items") if n["name"] == sn_name]
    assert [(n["arn"], n["id"]) for n in networks] == [(out["SnArn"], out["SnId"])], (
        f"ListServiceNetworks entries named {sn_name!r}: {networks!r}"
    )
    subs = paginate(vl, "list_access_log_subscriptions", "items",
                    resourceIdentifier=networks[0]["id"])
    assert [(s["arn"], s["id"]) for s in subs] == [(out["AlsArn"], out["AlsId"])], (
        f"subscriptions on {sn_name!r}: {subs!r}, Ref {out['AlsArn']!r}"
    )
    als = subs[0]
    als_arn = f"arn:{partition}:vpc-lattice:{ctx.region}:{ctx.account}:accesslogsubscription/"
    assert als["arn"] == als_arn + als["id"], f"subscription arn {als['arn']!r}"

    groups = _groups(logs, log_group_name)
    assert len(groups) == 1, f"DescribeLogGroups lists {len(groups)} for {log_group_name!r}"
    assert (groups[0]["arn"], groups[0]["retentionInDays"]) == (out["LgArn"], _RETENTION_DAYS), (
        f"log group (arn, retention) {(groups[0]['arn'], groups[0]['retentionInDays'])!r}"
    )
    got = (als["resourceId"], als["resourceArn"], als["destinationArn"])
    assert got == (networks[0]["id"], networks[0]["arn"], out["LgArn"]), (
        f"subscription (resourceId, resourceArn, destinationArn) {got!r}"
    )

    # Template tags plus the propagated stack tag, CloudFormation's aws:* tags dropped.
    for arn, tagged, key, value in (
        (networks[0]["arn"], vl, "sim2real-sn", sn_name),
        (als["arn"], vl, "sim2real-als", sn_name),
    ):
        got_tags = _own_tags(tagged.list_tags_for_resource(resourceArn=arn)["tags"])
        assert got_tags == {"sim2real": stack, key: value}, f"tags of {arn!r}: {got_tags!r}"
    lg_tags = _own_tags(logs.list_tags_for_resource(resourceArn=groups[0]["logGroupArn"])["tags"])
    assert lg_tags == {"sim2real": stack, "sim2real-lg": log_group_name}, f"tags {lg_tags!r}"

    # Child first: an update dropping only the subscription removes it while the network answers.
    als_id = als["id"]
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(sn_name, log_group_name, with_subscription=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"subscription-removing update ended {status!r}"
    als_gone = ("ResourceNotFoundException", f"AccessLogSubscription {als_id} cannot be found.")
    expect_error(lambda: vl.get_access_log_subscription(accessLogSubscriptionIdentifier=als_id),
                 *als_gone)
    left = paginate(vl, "list_access_log_subscriptions", "items",
                    resourceIdentifier=networks[0]["id"])
    assert left == [], f"subscriptions still listed on the network: {left!r}"

    sn_id = networks[0]["id"]
    delete_stack(cfn, stack_id)
    sn_gone = ("ResourceNotFoundException", f"ServiceNetwork {sn_id} cannot be found.")
    expect_error(lambda: vl.get_service_network(serviceNetworkIdentifier=sn_id), *sn_gone)
    assert _groups(logs, log_group_name) == [], (
        f"log group {log_group_name!r} is still listed after the stack delete"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
