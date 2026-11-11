"""deploy-outposts-site-invalid-country-code-rejected-and-rolled-back."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-outposts-site-invalid-country-code-rejected-and-rolled-back"
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


# ---- Check-specific: the template, then run(). ----


def _address(country_code: str) -> dict:
    return {
        "ContactName": "Jane Doe",
        "ContactPhoneNumber": "+61255500000",
        "AddressLine1": "123 Any Street",
        "City": "Seattle",
        "StateOrRegion": "WA",
        "PostalCode": "98144",
        "CountryCode": country_code,
    }


def _template(name: str, tag_value: str, operating_country_code: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Site": {
                "Type": "AWS::Outposts::Site",
                "Properties": {
                    "Name": name,
                    "OperatingAddress": _address(operating_country_code),
                    "ShippingAddress": _address("US"),
                    "Tags": [{"Key": "sim2real-site", "Value": tag_value}],
                },
            },
        },
        "Outputs": {
            "SiteRef": {"Value": {"Ref": "Site"}},
            "SiteId": {"Value": {"Fn::GetAtt": ["Site", "SiteId"]}},
        },
    })


_VALIDATION_FAILED = (
    "Validation failed with 2 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)
_PATH = "/Resources/Site/Properties/OperatingAddress/CountryCode"
_VALIDATION_ROWS = sorted([
    ("Site", "PROPERTY_VALIDATION", "FAILED", "FAIL",
     "#/OperatingAddress/CountryCode: expected maxLength: 2, actual: 3", _PATH),
    ("Site", "PROPERTY_VALIDATION", "FAILED", "FAIL",
     "Property value [USA] does not match pattern: ^[A-Z]{2}$", _PATH),
])


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Outposts::Site whose OperatingAddress.CountryCode is 3 letters fails
    pre-deployment validation on that property's length and pattern, creating no site; the same
    template with a 2-letter CountryCode succeeds and reads back through Outposts.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-outposts-site.html
    """
    outposts = ctx.client("outposts")
    cf = ctx.client("cloudformation")
    bad_stack = ctx.unique_name("sim2real-cfnoutsitebad-")
    bad_name = ctx.unique_name("sim2real-cfnoutsitebad-name-")

    bad_id = create_stack(ctx, cf, bad_stack, _template(bad_name, CHECK, "USA"))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"

    events = stack_events(cf, bad_id)
    reason = failed_reason(events, bad_stack)
    assert reason == _VALIDATION_FAILED, f"unexpected validation failure reason: {reason!r}"

    # The two errors are CountryCode's schema maxLength and pattern, on that one property.
    rows = validation_rows(cf, bad_id)
    assert rows == _VALIDATION_ROWS, (
        f"validation errors of the create: expected {_VALIDATION_ROWS!r}, got {rows!r}"
    )

    site_resources = [r for r in cf.describe_stack_resources(StackName=bad_id)["StackResources"]
                      if r["LogicalResourceId"] == "Site"]
    assert site_resources == [], (
        f"expected no Site resource under a rolled-back stack, got {site_resources!r}"
    )

    # Effect absent, before the check's own delete: no site carries the rejected name.
    named = [s for s in paginate(outposts, "list_sites", "Sites") if s.get("Name") == bad_name]
    assert named == [], f"ListSites lists {named!r} under {bad_name!r} after a rejected CREATE"

    delete_stack(cf, bad_id)

    # Positive control: the identical mechanism, given a valid 2-letter CountryCode, succeeds.
    good_name = ctx.unique_name("sim2real-cfnoutsitegood-name-")
    good_id = create_stack(ctx, cf, ctx.unique_name("sim2real-cfnoutsitegood-"),
                           _template(good_name, CHECK, "US"))
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", (
        f"the control stack ended {status!r}: {decisive_rows(stack_events(cf, good_id))!r}"
    )
    good_outputs = stack_outputs(cf, good_id)
    listed = [s["SiteArn"] for s in paginate(outposts, "list_sites", "Sites")
              if s.get("Name") == good_name]
    assert listed == [good_outputs["SiteRef"]], (
        f"ListSites lists {listed!r} under {good_name!r}; Ref is {good_outputs['SiteRef']!r}"
    )
    good_site_id = good_outputs["SiteId"]
    control = outposts.get_site(SiteId=good_site_id)["Site"]
    assert control["SiteArn"] == good_outputs["SiteRef"], (
        f"expected the control site's Ref {good_outputs['SiteRef']!r} to equal GetSite's SiteArn "
        f"{control['SiteArn']!r}"
    )
    assert control["Name"] == good_name, (
        f"expected the control site {good_site_id!r} to have Name {good_name!r}, "
        f"GetSite reports {control.get('Name')!r}"
    )
    assert control["OperatingAddressCountryCode"] == "US", (
        f"expected the control site's OperatingAddressCountryCode 'US', got "
        f"{control.get('OperatingAddressCountryCode')!r}"
    )
    want_address = _address("US")
    operating = outposts.get_site_address(SiteId=good_site_id, AddressType="OPERATING_ADDRESS")
    got_address = {k: operating["Address"].get(k) for k in want_address}
    assert got_address == want_address, (
        f"expected the control site's operating address {want_address!r}, got {got_address!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
