"""deploy-elasticache-serverlesscache-and-serverlesscachesnapshot-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-elasticache-serverlesscache-and-serverlesscachesnapshot-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "elasticache"]

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


_VPC_CIDR = "10.213.0.0/16"
_SUBNET_CIDRS = ["10.213.1.0/24", "10.213.2.0/24"]
_CREATE_TIMEOUT_S = 1500.0


def _cache_not_found(cache_name: str) -> tuple[str, str]:
    return ("ServerlessCacheNotFoundFault", f"Serverless cache with name {cache_name} not found.")


def _snapshot_not_found(snapshot_name: str) -> tuple[str, str]:
    return ("ServerlessCacheSnapshotNotFoundFault",
            f"Serverless Cache Snapshot with name {snapshot_name} not found")


def _template(cache_name: str, snapshot_name: str, with_snapshot: bool = True) -> str:
    az = [{"Fn::Select": [i, {"Fn::GetAZs": ""}]} for i in range(2)]
    resources = {
        "Vpc": {"Type": "AWS::EC2::VPC", "Properties": {"CidrBlock": _VPC_CIDR}},
        "SubnetA": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDRS[0], "AvailabilityZone": az[0]}},
        "SubnetB": {"Type": "AWS::EC2::Subnet", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "CidrBlock": _SUBNET_CIDRS[1], "AvailabilityZone": az[1]}},
        "SecurityGroup": {"Type": "AWS::EC2::SecurityGroup", "Properties": {
            "VpcId": {"Ref": "Vpc"}, "GroupDescription": "sim2real throwaway cache security group"}},
        "Cache": {"Type": "AWS::ElastiCache::ServerlessCache", "Properties": {
            "ServerlessCacheName": cache_name, "Engine": "valkey",
            "SubnetIds": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
            "SecurityGroupIds": [{"Ref": "SecurityGroup"}]}},
    }
    outputs = {
        "SubnetA": {"Value": {"Ref": "SubnetA"}},
        "SubnetB": {"Value": {"Ref": "SubnetB"}},
        "SecurityGroupId": {"Value": {"Ref": "SecurityGroup"}},
        "CacheName": {"Value": {"Ref": "Cache"}},
        "CacheArn": {"Value": {"Fn::GetAtt": ["Cache", "ARN"]}},
    }
    if with_snapshot:
        resources["Snapshot"] = {"Type": "AWS::ElastiCache::ServerlessCacheSnapshot",
                                 "Properties": {"ServerlessCacheSnapshotName": snapshot_name,
                                                "ServerlessCacheName": {"Ref": "Cache"}}}
        outputs["SnapshotArn"] = {"Value": {"Ref": "Snapshot"}}
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09", "Resources": resources, "Outputs": outputs,
    })


def _settled(read, timeout_s: float = 900.0) -> dict:
    """``read()`` polled (bounded) until its Status is 'available'."""
    deadline = time.monotonic() + timeout_s
    while True:
        item = read()
        if item["Status"] == "available":
            return item
        assert time.monotonic() < deadline, f"still {item['Status']!r} after {timeout_s:.0f}s"
        time.sleep(5)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation ElastiCache ServerlessCacheSnapshot of a stack's serverless cache reads back.

    The snapshot's Ref and source cache and the cache's subnets and group match; an update
    dropping the snapshot keeps the cache available, and the stack delete removes the cache.
    """
    ec = ctx.client("elasticache")
    cfn = ctx.client("cloudformation")
    cache_name = ctx.unique_name("sim2real-ecslsn-")
    snapshot_name = ctx.unique_name("sim2real-ecslsn-")

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-ecslsn-"),
                            _template(cache_name, snapshot_name))
    status = wait_stack(cfn, stack_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    assert out["CacheName"] == cache_name, f"CacheName Ref {out['CacheName']!r}"

    def cache_read() -> dict:
        caches = ec.describe_serverless_caches(ServerlessCacheName=cache_name)["ServerlessCaches"]
        assert len(caches) == 1, f"DescribeServerlessCaches({cache_name!r}) returned {caches!r}"
        return caches[0]

    cache = _settled(cache_read)
    got = (cache["ARN"], cache["Engine"], sorted(cache["SubnetIds"]), cache["SecurityGroupIds"])
    want = (out["CacheArn"], "valkey", sorted([out["SubnetA"], out["SubnetB"]]),
            [out["SecurityGroupId"]])
    assert got == want, f"serverless cache reads {got!r}, expected {want!r}"

    def snapshot_read() -> dict:
        snaps = paginate(ec, "describe_serverless_cache_snapshots", "ServerlessCacheSnapshots",
                         ServerlessCacheName=cache_name)
        mine = [s for s in snaps if s["ServerlessCacheSnapshotName"] == snapshot_name]
        assert len(mine) == 1, f"snapshots of {cache_name!r}: {snaps!r}"
        return mine[0]

    snap = _settled(snapshot_read)
    got = (snap["ARN"], snap["ServerlessCacheConfiguration"]["ServerlessCacheName"])
    assert got == (out["SnapshotArn"], cache_name), f"snapshot reads {got!r}"

    # The snapshot's own delete: an update dropping it while the cache stays available.
    cfn.update_stack(StackName=stack_id,
                     TemplateBody=_template(cache_name, snapshot_name, with_snapshot=False))
    status = wait_stack(cfn, stack_id, timeout_s=_CREATE_TIMEOUT_S)
    assert status == "UPDATE_COMPLETE", f"snapshot-removing update ended {status!r}"
    until_raises(lambda: ec.describe_serverless_cache_snapshots(
        ServerlessCacheSnapshotName=snapshot_name), timeout_s=300.0)
    snapshot_gone = _snapshot_not_found(snapshot_name)
    expect_error(
        lambda: ec.describe_serverless_cache_snapshots(ServerlessCacheSnapshotName=snapshot_name),
        *snapshot_gone,
    )
    assert cache_read()["Status"] == "available", "the cache survives the snapshot's delete"

    delete_stack(cfn, stack_id)
    until_raises(lambda: ec.describe_serverless_caches(ServerlessCacheName=cache_name),
                 timeout_s=600.0)
    cache_gone = _cache_not_found(cache_name)
    expect_error(lambda: ec.describe_serverless_caches(ServerlessCacheName=cache_name),
                 *cache_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
