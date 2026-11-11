"""deploy-medialive-cluster-and-channel-placement-group-round-trip-and-delete."""
from __future__ import annotations

import json
import secrets
import time

from behavioral_harness import tags

CHECK = "deploy-medialive-cluster-and-channel-placement-group-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "medialive"]

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

_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{
        "Effect": "Allow",
        "Principal": {"Service": "medialive.amazonaws.com"},
        "Action": "sts:AssumeRole",
    }],
}


def _template(network_name, cidr, cluster_name, cpg_name):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Network": {
                "Type": "AWS::MediaLive::Network",
                "Properties": {"Name": network_name, "IpPools": [{"Cidr": cidr}]},
            },
            "ClusterRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {"AssumeRolePolicyDocument": _TRUST},
            },
            "Cluster": {
                "Type": "AWS::MediaLive::Cluster",
                "Properties": {
                    "Name": cluster_name,
                    "ClusterType": "ON_PREMISES",
                    "InstanceRoleArn": {"Fn::GetAtt": ["ClusterRole", "Arn"]},
                    "NetworkSettings": {
                        "DefaultRoute": "eth0",
                        "InterfaceMappings": [
                            {"LogicalInterfaceName": "eth0", "NetworkId": {"Ref": "Network"}},
                        ],
                    },
                },
            },
            "ChannelPlacementGroup": {
                "Type": "AWS::MediaLive::ChannelPlacementGroup",
                "Properties": {"ClusterId": {"Ref": "Cluster"}, "Name": cpg_name},
            },
        },
        "Outputs": {
            "NetworkId": {"Value": {"Ref": "Network"}},
            "NetworkArn": {"Value": {"Fn::GetAtt": ["Network", "Arn"]}},
            "RoleArn": {"Value": {"Fn::GetAtt": ["ClusterRole", "Arn"]}},
            "ClusterId": {"Value": {"Ref": "Cluster"}},
            "ClusterArn": {"Value": {"Fn::GetAtt": ["Cluster", "Arn"]}},
            "CpgRef": {"Value": {"Ref": "ChannelPlacementGroup"}},
            "CpgId": {"Value": {"Fn::GetAtt": ["ChannelPlacementGroup", "Id"]}},
            "CpgArn": {"Value": {"Fn::GetAtt": ["ChannelPlacementGroup", "Arn"]}},
        },
    })


def _own(items, name):
    """The entries of a paged list named ``name`` (names are unique per run)."""
    return [i for i in items if i["Name"] == name]


def _wait_state(read, want, timeout_s=120.0):
    """Poll ``read()["State"]`` every 2 s until ``want``; return it, or fail at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = read()
        if got["State"] == want:
            return got
        if time.monotonic() > deadline:
            raise AssertionError(
                f"State {got['State']!r}, expected {want!r} after {timeout_s:.0f}s"
            )
        time.sleep(2)


@tags("axis:happy-path", "cap:c7", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation MediaLive Network, Cluster and ChannelPlacementGroup read back through
    MediaLive with the template's values and Ids that match the paged lists by name; deleting the
    stack leaves each in its documented DELETED tombstone state.
    """
    cfn = ctx.client("cloudformation")
    medialive = ctx.client("medialive")
    network_name = ctx.unique_name("sim2real-behav-clusnet-")
    cluster_name = ctx.unique_name("sim2real-behav-cluster-")
    cpg_name = ctx.unique_name("sim2real-behav-cpg-")
    cidr = f"10.201.{secrets.randbelow(256)}.0/24"

    stack_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cfnmlclus-"),
                            _template(network_name, cidr, cluster_name, cpg_name),
                            Capabilities=["CAPABILITY_IAM"])
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    out = stack_outputs(cfn, stack_id)
    network_id, cluster_id = out["NetworkId"], out["ClusterId"]

    # Refs against the paged lists by name, never a read keyed by the Ref.
    networks = _own(paginate(medialive, "list_networks", "Networks"), network_name)
    assert [n["Id"] for n in networks] == [network_id], f"ListNetworks by name: {networks!r}"
    clusters = _own(paginate(medialive, "list_clusters", "Clusters"), cluster_name)
    assert [c["Id"] for c in clusters] == [cluster_id], f"ListClusters by name: {clusters!r}"
    cpgs = _own(paginate(medialive, "list_channel_placement_groups", "ChannelPlacementGroups",
                         ClusterId=clusters[0]["Id"]), cpg_name)
    assert [g["Id"] for g in cpgs] == [out["CpgId"]], f"ListChannelPlacementGroups: {cpgs!r}"
    assert out["CpgRef"] == f"{cpgs[0]['Id']}|{clusters[0]['Id']}", (
        f"ChannelPlacementGroup Ref {out['CpgRef']!r} is not '<Id>|<ClusterId>' of the listing"
    )

    network = medialive.describe_network(NetworkId=network_id)
    got = (network["Arn"], network["Name"], network["IpPools"])
    assert got == (out["NetworkArn"], network_name, [{"Cidr": cidr}]), f"network reads {got!r}"

    cluster = medialive.describe_cluster(ClusterId=cluster_id)
    got = (cluster["Arn"], cluster["Name"], cluster["ClusterType"], cluster["InstanceRoleArn"])
    want = (out["ClusterArn"], cluster_name, "ON_PREMISES", out["RoleArn"])
    assert got == want, f"cluster reads {got!r}, expected {want!r}"
    settings = cluster["NetworkSettings"]
    want_settings = {"DefaultRoute": "eth0",
                     "InterfaceMappings": [{"LogicalInterfaceName": "eth0",
                                            "NetworkId": networks[0]["Id"]}]}
    assert settings == want_settings, f"cluster NetworkSettings {settings!r}"

    cpg = medialive.describe_channel_placement_group(
        ClusterId=cluster_id, ChannelPlacementGroupId=out["CpgId"]
    )
    got = (cpg["Arn"], cpg["Name"], cpg["ClusterId"])
    assert got == (out["CpgArn"], cpg_name, cluster_id), f"placement group reads {got!r}"

    # MediaLive keeps a deleted Network, Cluster and placement group as a DELETED tombstone.
    delete_stack(cfn, stack_id)
    gone = _wait_state(lambda: medialive.describe_channel_placement_group(
        ClusterId=cluster_id, ChannelPlacementGroupId=out["CpgId"]), "DELETED")
    assert gone["State"] == "DELETED", f"deleted placement group State {gone['State']!r}"
    gone = _wait_state(lambda: medialive.describe_cluster(ClusterId=cluster_id), "DELETED")
    assert gone["State"] == "DELETED", f"deleted cluster State {gone['State']!r}"
    gone = _wait_state(lambda: medialive.describe_network(NetworkId=network_id), "DELETED")
    assert gone["State"] == "DELETED", f"deleted network State {gone['State']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
