"""deploy-cfn-codeconnections-connection-and-host-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-codeconnections-connection-and-host-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "codeconnections"]

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

def _template(connection_name, host_name, endpoint):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Connection": {"Type": "AWS::CodeConnections::Connection", "Properties": {
                "ConnectionName": connection_name, "ProviderType": "GitHub"}},
            "Host": {"Type": "AWS::CodeConnections::Host", "Properties": {
                "Name": host_name, "ProviderType": "GitHubEnterpriseServer",
                "ProviderEndpoint": endpoint}},
        },
        "Outputs": {
            "ConnectionRef": {"Value": {"Ref": "Connection"}},
            "ConnectionArnAtt": {"Value": {"Fn::GetAtt": ["Connection", "ConnectionArn"]}},
            "ConnectionStatusAtt": {"Value": {"Fn::GetAtt": ["Connection", "ConnectionStatus"]}},
            "HostArn": {"Value": {"Ref": "Host"}},
            "HostIdAtt": {"Value": {"Fn::GetAtt": ["Host", "HostId"]}},
            "HostStatusAtt": {"Value": {"Fn::GetAtt": ["Host", "Status"]}},
        },
    })


def _all(call, key, **kw):
    """Every ``key`` entry across the NextToken pages of a list without a paginator."""
    items, token = [], None
    while True:
        page = call(**kw, **({"NextToken": token} if token else {}))
        items += page[key]
        token = page.get("NextToken")
        if not token:
            return items


@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation CodeConnections Connection and Host read back, then the stack delete removes both.

    Each Ref and GetAtt matches the CodeConnections list entry found by name, and every templated
    property reads back; after the delete each returns its exact ResourceNotFoundException.
    """
    cfn = ctx.client("cloudformation")
    cc = ctx.client("codeconnections")
    connection_name = ctx.unique_name("sim2real-behav-conn-")
    host_name = ctx.unique_name("sim2real-behav-host-")
    endpoint = f"https://{ctx.unique_name('sim2real-behav-ghe-')}.example.com"

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-behav-cfn-cc-"),
                            _template(connection_name, host_name, endpoint))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)

    connections = [c for c in _all(cc.list_connections, "Connections", ProviderTypeFilter="GitHub")
                   if c["ConnectionName"] == connection_name]
    got = [(c["ConnectionArn"], c["ProviderType"], c["ConnectionStatus"], c["OwnerAccountId"])
           for c in connections]
    want = [(out["ConnectionRef"], "GitHub", "PENDING", ctx.account)]
    assert got == want, f"ListConnections named {connection_name!r}: {got!r}, expected {want!r}"
    assert (out["ConnectionArnAtt"], out["ConnectionStatusAtt"]) == (out["ConnectionRef"], "PENDING"), (
        f"Connection GetAtts {out['ConnectionArnAtt']!r}, {out['ConnectionStatusAtt']!r}"
    )

    hosts = [h for h in _all(cc.list_hosts, "Hosts") if h["Name"] == host_name]
    got = [(h["HostArn"], h["ProviderType"], h["ProviderEndpoint"], h["Status"]) for h in hosts]
    want = [(out["HostArn"], "GitHubEnterpriseServer", endpoint, out["HostStatusAtt"])]
    assert got == want and out["HostStatusAtt"] == "PENDING", (
        f"ListHosts named {host_name!r}: {got!r}, expected {want!r}"
    )
    host_arn = hosts[0]["HostArn"]
    assert host_arn.rsplit("/", 1)[-1] == out["HostIdAtt"], (
        f"GetAtt HostId {out['HostIdAtt']!r} is not the listed host ARN's id {host_arn!r}"
    )

    delete_stack(cfn, stack_id)
    connection_arn = out["ConnectionRef"]
    connection_gone = ("ResourceNotFoundException", "No connection exists with the ARN")
    expect_error(lambda: cc.get_connection(ConnectionArn=connection_arn), *connection_gone)
    host_gone = ("ResourceNotFoundException", f"No host exists with the ARN: {host_arn}")
    expect_error(lambda: cc.get_host(HostArn=host_arn), *host_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
