"""deploy-cloudformation-internetmonitor-monitor-round-trip-update-and-delete."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cloudformation-internetmonitor-monitor-round-trip-update-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "internetmonitor"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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


def until_raises(fn, timeout_s=90.0):
    """Poll ``fn()`` every 2 s until it raises a ClientError (an eventually consistent delete).

    Grade the error afterwards with expect_error; a success past the deadline fails.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError:
            return
        if time.monotonic() > deadline:
            raise AssertionError(f"still answering after {timeout_s:.0f}s: {result!r}")
        time.sleep(2)


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


def is_subsequence(want, rows):
    """True when ``want`` occurs in ``rows`` in order (gaps allowed)."""
    it = iter(rows)
    return all(w in it for w in want)


def masked(text, account, *names):
    """``text`` masking only Request ID, RequestToken, SDK Attempt Count, account, run names."""
    text = re.sub(r"((?:Extended )?Request ID): [^,;)]+", r"\1: <id>", text)
    text = re.sub(r"RequestToken: [0-9a-f-]+", "RequestToken: <token>", text)
    text = re.sub(r"SDK Attempt Count: \d+", "SDK Attempt Count: <n>", text)
    text = text.replace(account, "<account>")
    for name in sorted(names, key=len, reverse=True):
        text = text.replace(name, "<name>")
    return text


# ---- Check-specific: the template, then run(). ----

_NOT_FOUND = (
    "ResourceNotFoundException",
    "No resource found for account <account> and resource monitor/<name>",
)


def _template(monitor_name, max_city_networks):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Monitor": {
                "Type": "AWS::InternetMonitor::Monitor",
                "Properties": {
                    "MonitorName": monitor_name,
                    "MaxCityNetworksToMonitor": max_city_networks,
                    "Status": "ACTIVE",
                    "Tags": [{"Key": "sim2real-monitor", "Value": monitor_name}],
                },
            },
        },
        "Outputs": {
            "MonitorRef": {"Value": {"Ref": "Monitor"}},
            "MonitorArn": {"Value": {"Fn::GetAtt": ["Monitor", "MonitorArn"]}},
            "MonitorCreatedAt": {"Value": {"Fn::GetAtt": ["Monitor", "CreatedAt"]}},
        },
    })


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Internet Monitor monitor reads back through Internet Monitor, updates
    one property in place on the same monitor, then the delete removes it.
    """
    cf = ctx.client("cloudformation")
    im = ctx.client("internetmonitor")
    monitor = ctx.unique_name("sim2real-cfnim-rt-")

    stack_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfnim-rt-stack-"),
                            _template(monitor, 1))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    rows = decisive_rows(stack_events(cf, stack_id), "Monitor")
    assert is_subsequence([("Monitor", "CREATE_COMPLETE")], rows), (
        f"expected a Monitor CREATE_COMPLETE row, got {rows!r}"
    )
    out = stack_outputs(cf, stack_id)

    # Ref against an independent read (ListMonitors, paginated), never a read keyed by the Ref.
    listed = [m for m in paginate(im, "list_monitors", "Monitors", MaxResults=25)
              if m["MonitorName"] == monitor]
    assert len(listed) == 1, f"ListMonitors found {listed!r} for the monitor named {monitor!r}"
    assert out["MonitorRef"] == monitor, f"Ref {out['MonitorRef']!r} != MonitorName {monitor!r}"

    created = im.get_monitor(MonitorName=monitor)
    # Read-only GetAtt == the service value.
    assert out["MonitorArn"] == created["MonitorArn"] == listed[0]["MonitorArn"], (
        f"GetAtt MonitorArn {out['MonitorArn']!r}, GetMonitor {created['MonitorArn']!r}, "
        f"ListMonitors {listed[0]['MonitorArn']!r}"
    )
    assert out["MonitorCreatedAt"] == created["CreatedAt"].strftime("%Y-%m-%dT%H:%M:%SZ"), (
        f"GetAtt CreatedAt {out['MonitorCreatedAt']!r} != GetMonitor CreatedAt {created['CreatedAt']!r}"
    )

    # Every templated property reads back through Internet Monitor, including Status, which the
    # service only reaches once it finishes its own PENDING-to-ACTIVE transition on create.
    got = {"Status": created["Status"], "MaxCityNetworksToMonitor": created["MaxCityNetworksToMonitor"],
           "Resources": created["Resources"]}
    assert got == {"Status": "ACTIVE", "MaxCityNetworksToMonitor": 1, "Resources": []}, (
        f"monitor reads {got!r}"
    )
    monitor_tags = {k: v for k, v in created["Tags"].items() if not k.startswith("aws:")}
    assert monitor_tags == {"sim2real": stack_id.split("/")[1], "sim2real-monitor": monitor}, (
        f"tags {monitor_tags!r}"
    )

    # Update in place: a server-minted identity (CreatedAt) proves the SAME monitor, not a
    # replacement, while the templated property it changed reads back with the new value.
    cf.update_stack(StackName=stack_id, TemplateBody=_template(monitor, 5))
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", f"update ended {status!r}"
    after = im.get_monitor(MonitorName=monitor)
    assert after["CreatedAt"] == created["CreatedAt"], (
        f"CreatedAt changed from {created['CreatedAt']!r} to {after['CreatedAt']!r}: not the same monitor"
    )
    assert after["MaxCityNetworksToMonitor"] == 5, (
        f"MaxCityNetworksToMonitor after update is {after['MaxCityNetworksToMonitor']!r}, expected 5"
    )

    delete_stack(cf, stack_id)
    until_raises(lambda: im.get_monitor(MonitorName=monitor))
    try:
        im.get_monitor(MonitorName=monitor)
    except ClientError as exc:
        got = (exc.response["Error"]["Code"],
               masked(exc.response["Error"]["Message"], ctx.account, monitor))
        assert got == _NOT_FOUND, f"deleted monitor read back as {got!r}, expected {_NOT_FOUND!r}"
    else:
        raise AssertionError("expected ResourceNotFoundException, but get_monitor succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
