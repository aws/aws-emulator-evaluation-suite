"""deploy-outposts-site-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-outposts-site-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "outposts"]

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


def _address(city: str, state: str, postal: str) -> dict:
    return {
        "ContactName": "Jane Doe",
        "ContactPhoneNumber": "+61255500000",
        "AddressLine1": "123 Any Street",
        "City": city,
        "StateOrRegion": state,
        "PostalCode": postal,
        "CountryCode": "US",
    }


_OPERATING = ("Seattle", "WA", "98144")
_SHIPPING = ("Portland", "OR", "97201")


def _rack_properties() -> dict:
    return {
        "PowerDrawKva": "POWER_15_KVA",
        "PowerPhase": "SINGLE_PHASE",
        "PowerConnector": "L6_30P",
        "PowerFeedDrop": "ABOVE_RACK",
        "UplinkGbps": "UPLINK_1G",
        "UplinkCount": "UPLINK_COUNT_1",
        "FiberOpticCableType": "SINGLE_MODE",
        "OpticalStandard": "OPTIC_1000BASE_LX",
        "MaximumSupportedWeightLbs": "NO_LIMIT",
    }


def _template(name: str, tag_value: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Site": {
                "Type": "AWS::Outposts::Site",
                "Properties": {
                    "Name": name,
                    "Description": "sim2real cloudformation outposts site check",
                    "OperatingAddress": _address(*_OPERATING),
                    "ShippingAddress": _address(*_SHIPPING),
                    "RackPhysicalProperties": _rack_properties(),
                    "Tags": [{"Key": "sim2real-site", "Value": tag_value}],
                },
            },
        },
        "Outputs": {
            "SiteRef": {"Value": {"Ref": "Site"}},
            "SiteArn": {"Value": {"Fn::GetAtt": ["Site", "SiteArn"]}},
            "SiteId": {"Value": {"Fn::GetAtt": ["Site", "SiteId"]}},
        },
    })


_STACK_GONE = "Stack with id {} does not exist"


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Outposts::Site reaches CREATE_COMPLETE with Ref equal to the site's
    ARN and the template's properties readable through Outposts' own GetSite; deleting the stack
    removes the site, which GetSite then reports NotFoundException for.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-outposts-site.html
    """
    outposts = ctx.client("outposts")
    cf = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-cfnoutsite-")
    name = ctx.unique_name("sim2real-cfnoutsite-name-")

    stack_id = create_stack(ctx, cf, stack, _template(name, CHECK))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cf, stack_id))!r}"
    )

    outputs = stack_outputs(cf, stack_id)
    site_ref, site_arn_attr, site_id = outputs["SiteRef"], outputs["SiteArn"], outputs["SiteId"]
    # Ref against an independent read: ListSites by the declared name.
    listed = [s["SiteArn"] for s in paginate(outposts, "list_sites", "Sites") if s.get("Name") == name]
    assert listed == [site_ref], f"ListSites lists {listed!r} under {name!r}; Ref is {site_ref!r}"
    assert site_ref == site_arn_attr, (
        f"expected Ref {site_ref!r} to equal Fn::GetAtt SiteArn {site_arn_attr!r}"
    )

    got = outposts.get_site(SiteId=site_id)["Site"]
    assert got["SiteId"] == site_id, f"GetSite SiteId: expected {site_id!r}, got {got['SiteId']!r}"
    assert got["SiteArn"] == site_ref, (
        f"expected Ref {site_ref!r} to equal GetSite's own SiteArn {got['SiteArn']!r}"
    )
    assert got["Name"] == name, f"GetSite Name: expected {name!r}, got {got['Name']!r}"
    assert got["Description"] == "sim2real cloudformation outposts site check", (
        f"GetSite Description: unexpected value {got.get('Description')!r}"
    )
    site_tags = {k: v for k, v in got["Tags"].items() if not k.startswith("aws:")}
    assert site_tags == {"sim2real": stack, "sim2real-site": CHECK}, (
        f"GetSite Tags: unexpected value {got.get('Tags')!r}"
    )
    assert got["OperatingAddressCountryCode"] == "US", (
        f"GetSite OperatingAddressCountryCode: expected 'US', got {got.get('OperatingAddressCountryCode')!r}"
    )
    assert got["OperatingAddressStateOrRegion"] == "WA", (
        f"GetSite OperatingAddressStateOrRegion: expected 'WA', got {got.get('OperatingAddressStateOrRegion')!r}"
    )
    assert got["OperatingAddressCity"] == "Seattle", (
        f"GetSite OperatingAddressCity: expected 'Seattle', got {got.get('OperatingAddressCity')!r}"
    )
    rack = got["RackPhysicalProperties"]
    for key, value in _rack_properties().items():
        assert rack.get(key) == value, (
            f"GetSite RackPhysicalProperties.{key}: expected {value!r}, got {rack.get(key)!r}"
        )

    for address_type, parts in (("OPERATING_ADDRESS", _OPERATING), ("SHIPPING_ADDRESS", _SHIPPING)):
        want_address = _address(*parts)
        read = outposts.get_site_address(SiteId=site_id, AddressType=address_type)
        got_address = {k: read["Address"].get(k) for k in want_address}
        assert (read["AddressType"], got_address) == (address_type, want_address), (
            f"GetSiteAddress {address_type}: expected {want_address!r}, got "
            f"{(read['AddressType'], got_address)!r}"
        )

    resources = cf.describe_stack_resources(StackName=stack_id)["StackResources"]
    site_resources = [r for r in resources if r["LogicalResourceId"] == "Site"]
    assert len(site_resources) == 1, f"expected exactly one Site resource, got {site_resources!r}"
    assert site_resources[0]["PhysicalResourceId"] == site_arn_attr, (
        f"stack resource PhysicalResourceId {site_resources[0]['PhysicalResourceId']!r} does not "
        f"match Fn::GetAtt SiteArn {site_arn_attr!r}"
    )

    delete_stack(cf, stack_id)

    stack_gone = ("ValidationError", _STACK_GONE.format(stack))
    expect_error(lambda: cf.describe_stacks(StackName=stack), *stack_gone)
    site_not_found = ("NotFoundException", f"siteId={site_id}")
    expect_error(lambda: outposts.get_site(SiteId=site_id), *site_not_found)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
