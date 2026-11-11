"""deploy-networkmanager-core-resources-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-networkmanager-core-resources-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "networkmanager"]

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

_CHILDREN = (
    # (paged NetworkManager read of the global network's children, its result key)
    ("get_sites", "Sites"),
    ("get_devices", "Devices"),
    ("get_links", "Links"),
    ("get_link_associations", "LinkAssociations"),
    ("get_connections", "Connections"),
)


def _template(marker: str, children: bool = True) -> str:
    t = [{"Key": "sim2real-nm", "Value": marker}]
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "GlobalNetwork": {
                "Type": "AWS::NetworkManager::GlobalNetwork",
                "Properties": {"Description": marker, "Tags": t},
            },
            "Site": {
                "Type": "AWS::NetworkManager::Site",
                "Properties": {"GlobalNetworkId": {"Ref": "GlobalNetwork"}, "Tags": t},
            },
            "DeviceA": {
                "Type": "AWS::NetworkManager::Device",
                "Properties": {
                    "GlobalNetworkId": {"Ref": "GlobalNetwork"},
                    "SiteId": {"Fn::GetAtt": ["Site", "SiteId"]},
                    "Tags": t,
                },
            },
            "DeviceB": {
                "Type": "AWS::NetworkManager::Device",
                "Properties": {"GlobalNetworkId": {"Ref": "GlobalNetwork"}, "Tags": t},
            },
            "Link": {
                "Type": "AWS::NetworkManager::Link",
                "Properties": {
                    "GlobalNetworkId": {"Ref": "GlobalNetwork"},
                    "SiteId": {"Fn::GetAtt": ["Site", "SiteId"]},
                    "Bandwidth": {"DownloadSpeed": 50, "UploadSpeed": 10},
                    "Tags": t,
                },
            },
            "LinkAssociation": {
                "Type": "AWS::NetworkManager::LinkAssociation",
                "Properties": {
                    "GlobalNetworkId": {"Ref": "GlobalNetwork"},
                    "DeviceId": {"Fn::GetAtt": ["DeviceA", "DeviceId"]},
                    "LinkId": {"Fn::GetAtt": ["Link", "LinkId"]},
                },
            },
            "Connection": {
                "Type": "AWS::NetworkManager::Connection",
                "Properties": {
                    "GlobalNetworkId": {"Ref": "GlobalNetwork"},
                    "DeviceId": {"Fn::GetAtt": ["DeviceA", "DeviceId"]},
                    "ConnectedDeviceId": {"Fn::GetAtt": ["DeviceB", "DeviceId"]},
                    "Tags": t,
                },
            },
        },
        "Outputs": {
            "GlobalNetworkRef": {"Value": {"Ref": "GlobalNetwork"}},
            "GlobalNetworkArn": {"Value": {"Fn::GetAtt": ["GlobalNetwork", "Arn"]}},
            "SiteRef": {"Value": {"Ref": "Site"}},
            "SiteId": {"Value": {"Fn::GetAtt": ["Site", "SiteId"]}},
            "SiteArn": {"Value": {"Fn::GetAtt": ["Site", "SiteArn"]}},
            "DeviceARef": {"Value": {"Ref": "DeviceA"}},
            "DeviceAId": {"Value": {"Fn::GetAtt": ["DeviceA", "DeviceId"]}},
            "DeviceAArn": {"Value": {"Fn::GetAtt": ["DeviceA", "DeviceArn"]}},
            "DeviceBRef": {"Value": {"Ref": "DeviceB"}},
            "DeviceBId": {"Value": {"Fn::GetAtt": ["DeviceB", "DeviceId"]}},
            "DeviceBArn": {"Value": {"Fn::GetAtt": ["DeviceB", "DeviceArn"]}},
            "LinkRef": {"Value": {"Ref": "Link"}},
            "LinkId": {"Value": {"Fn::GetAtt": ["Link", "LinkId"]}},
            "LinkArn": {"Value": {"Fn::GetAtt": ["Link", "LinkArn"]}},
            "LinkAssociationRef": {"Value": {"Ref": "LinkAssociation"}},
            "ConnectionRef": {"Value": {"Ref": "Connection"}},
            "ConnectionId": {"Value": {"Fn::GetAtt": ["Connection", "ConnectionId"]}},
            "ConnectionArn": {"Value": {"Fn::GetAtt": ["Connection", "ConnectionArn"]}},
        },
    }
    if not children:
        template["Resources"] = {"GlobalNetwork": template["Resources"]["GlobalNetwork"]}
        template["Outputs"] = {k: v for k, v in template["Outputs"].items()
                               if k.startswith("GlobalNetwork")}
    return json.dumps(template)


def _own_tags(nm, arn):
    """The resource's tags other than CloudFormation's aws: system tags."""
    return {t["Key"]: t["Value"] for t in nm.list_tags_for_resource(ResourceArn=arn)["TagList"]
            if not t["Key"].startswith("aws:")}


def _wait_children_gone(nm, gn_id, timeout_s=120.0):
    """Poll each child read of the global network every 2 s until all list nothing; fail at the
    deadline naming what is left."""
    deadline = time.monotonic() + timeout_s
    while True:
        left = {key: rows for op, key in _CHILDREN
                if (rows := paginate(nm, op, key, GlobalNetworkId=gn_id))}
        if not left:
            return left
        if time.monotonic() > deadline:
            raise AssertionError(
                f"after dropping the children the global network still holds {left!r} "
                f"after {timeout_s:.0f}s"
            )
        time.sleep(2)


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation GlobalNetwork, Site, two Devices, Link, LinkAssociation and Connection
    match NetworkManager's reads (Ref, GetAtt, properties, tags); an update dropping the children
    removes each while the global network stays, and the stack delete removes the network.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-networkmanager-globalnetwork.html
    """
    nm = ctx.client("networkmanager")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-nmcore-")

    stack_id = create_stack(ctx, cfn, stack, _template(stack))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    want_tags = {"sim2real": stack, "sim2real-nm": stack}

    # GlobalNetwork Ref against the paged DescribeGlobalNetworks entry carrying this run's marker.
    gns = [g for g in paginate(nm, "describe_global_networks", "GlobalNetworks")
           if g.get("Description") == stack]
    assert len(gns) == 1, f"DescribeGlobalNetworks by Description: {gns!r}"
    gn_id = gns[0]["GlobalNetworkId"]
    got = (outputs["GlobalNetworkRef"], outputs["GlobalNetworkArn"], gns[0]["State"])
    assert got == (gn_id, gns[0]["GlobalNetworkArn"], "AVAILABLE"), (
        f"GlobalNetwork Ref/Arn/State {got!r}, listed {gns[0]!r}"
    )
    got_tags = _own_tags(nm, gns[0]["GlobalNetworkArn"])
    assert got_tags == want_tags, f"GlobalNetwork tags {got_tags!r}, expected {want_tags!r}"

    # Each child from the paged read of the global network, never a read keyed by its Ref.
    sites = paginate(nm, "get_sites", "Sites", GlobalNetworkId=gn_id)
    assert len(sites) == 1, f"GetSites of the global network: {sites!r}"
    site = sites[0]
    got = (outputs["SiteRef"], outputs["SiteId"], outputs["SiteArn"], site["State"])
    want = (f"{gn_id}|{site['SiteId']}", site["SiteId"], site["SiteArn"], "AVAILABLE")
    assert got == want, f"Site Ref/Id/Arn/State {got!r}, expected {want!r}"

    devices = paginate(nm, "get_devices", "Devices", GlobalNetworkId=gn_id)
    by_site = {d.get("SiteId"): d for d in devices}
    assert len(devices) == 2 and set(by_site) == {site["SiteId"], None}, (
        f"GetDevices of the global network: {devices!r}"
    )
    dev_a, dev_b = by_site[site["SiteId"]], by_site[None]
    got = (outputs["DeviceARef"], outputs["DeviceAId"], outputs["DeviceAArn"], dev_a["State"],
           outputs["DeviceBRef"], outputs["DeviceBId"], outputs["DeviceBArn"], dev_b["State"])
    want = (f"{gn_id}|{dev_a['DeviceId']}", dev_a["DeviceId"], dev_a["DeviceArn"], "AVAILABLE",
            f"{gn_id}|{dev_b['DeviceId']}", dev_b["DeviceId"], dev_b["DeviceArn"], "AVAILABLE")
    assert got == want, f"Device Refs/Ids/Arns/States {got!r}, expected {want!r}"

    links = paginate(nm, "get_links", "Links", GlobalNetworkId=gn_id)
    assert len(links) == 1, f"GetLinks of the global network: {links!r}"
    link = links[0]
    got = (outputs["LinkRef"], outputs["LinkId"], outputs["LinkArn"], link["SiteId"],
           link["Bandwidth"], link["State"])
    want = (f"{gn_id}|{link['LinkId']}", link["LinkId"], link["LinkArn"], site["SiteId"],
            {"DownloadSpeed": 50, "UploadSpeed": 10}, "AVAILABLE")
    assert got == want, f"Link Ref/Id/Arn/SiteId/Bandwidth/State {got!r}, expected {want!r}"

    assocs = paginate(nm, "get_link_associations", "LinkAssociations", GlobalNetworkId=gn_id)
    got = [(a["DeviceId"], a["LinkId"], a["LinkAssociationState"]) for a in assocs]
    assert got == [(dev_a["DeviceId"], link["LinkId"], "AVAILABLE")], f"link associations {got!r}"
    assert outputs["LinkAssociationRef"] == f"{gn_id}|{dev_a['DeviceId']}|{link['LinkId']}", (
        f"LinkAssociation Ref {outputs['LinkAssociationRef']!r}"
    )

    conns = paginate(nm, "get_connections", "Connections", GlobalNetworkId=gn_id)
    assert len(conns) == 1, f"GetConnections of the global network: {conns!r}"
    conn = conns[0]
    got = (outputs["ConnectionRef"], outputs["ConnectionArn"], outputs["ConnectionId"],
           conn["DeviceId"], conn["ConnectedDeviceId"], conn["State"])
    want = (conn["ConnectionArn"], conn["ConnectionArn"], conn["ConnectionId"],
            dev_a["DeviceId"], dev_b["DeviceId"], "AVAILABLE")
    assert got == want, f"Connection Ref/Arn/Id/devices/State {got!r}, expected {want!r}"

    for label, arn in (("Site", site["SiteArn"]), ("DeviceA", dev_a["DeviceArn"]),
                       ("DeviceB", dev_b["DeviceArn"]), ("Link", link["LinkArn"]),
                       ("Connection", conn["ConnectionArn"])):
        got_tags = _own_tags(nm, arn)
        assert got_tags == want_tags, f"{label} tags {got_tags!r}, expected {want_tags!r}"

    # Children before the parent: an update keeping only the global network removes each child
    # type from NetworkManager while the global network still answers.
    cfn.update_stack(StackName=stack_id, TemplateBody=_template(stack, children=False))
    status = wait_stack(cfn, stack_id)
    assert status == "UPDATE_COMPLETE", f"child-removing update ended {status!r}"
    left = _wait_children_gone(nm, gn_id)
    assert left == {}, f"after dropping the children the global network still holds {left!r}"
    still = [g["GlobalNetworkId"] for g in paginate(nm, "describe_global_networks",
                                                     "GlobalNetworks", GlobalNetworkIds=[gn_id])]
    assert still == [gn_id], f"the global network after the child update lists as {still!r}"

    delete_stack(cfn, stack_id)
    after = paginate(nm, "describe_global_networks", "GlobalNetworks", GlobalNetworkIds=[gn_id])
    assert after == [], f"DescribeGlobalNetworks({gn_id!r}) after the stack delete: {after!r}"
    gn_gone = ("ValidationException", "Global network not found.")
    expect_error(lambda: nm.get_sites(GlobalNetworkId=gn_id), *gn_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
