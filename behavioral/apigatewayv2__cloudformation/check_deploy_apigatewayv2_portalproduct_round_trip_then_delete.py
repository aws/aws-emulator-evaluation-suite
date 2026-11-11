"""deploy-apigatewayv2-portalproduct-round-trip-then-delete."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-apigatewayv2-portalproduct-round-trip-then-delete"
GROUP = "deploy"
SERVICES = ["apigatewayv2", "cloudformation"]

# ---- CloudFormation helpers: copied verbatim; unused ones deleted. ----

_TERMINAL = frozenset({
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
    "DELETE_COMPLETE", "DELETE_FAILED", "UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE", "IMPORT_ROLLBACK_COMPLETE",
    "IMPORT_ROLLBACK_FAILED",
})
_DELETE_BUDGET_S = 600.0  # per stack; at most two stacks fit the suites' 1800 s cleanup budget


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


def paginate(client, op, key, **kw):
    """Every item under ``key`` across all pages of ``op``; presence and absence read every page.

    A ``key`` the operation's output does not declare fails instead of reading as [].
    """
    model = client.meta.service_model.operation_model(client.meta.method_to_api_mapping[op])
    assert key in model.output_shape.members, f"{op} output has no member {key!r}"
    return [x for page in client.get_paginator(op).paginate(**kw) for x in page.get(key, [])]


def stack_events(cf, stack_id):
    """Every DescribeStackEvents row of the stack, oldest first."""
    return paginate(cf, "describe_stack_events", "StackEvents", StackName=stack_id)[::-1]


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

_DESCRIPTION = "a developer-portal product created by a round-trip check"


def _template(display_name: str, description: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Product": {
                "Type": "AWS::ApiGatewayV2::PortalProduct",
                "Properties": {"DisplayName": display_name, "Description": description},
            },
        },
        "Outputs": {
            "ProductRef": {"Value": {"Ref": "Product"}},
            "ProductId": {"Value": {"Fn::GetAtt": ["Product", "PortalProductId"]}},
            "ProductArn": {"Value": {"Fn::GetAtt": ["Product", "PortalProductArn"]}},
            "ProductLastModified": {"Value": {"Fn::GetAtt": ["Product", "LastModified"]}},
        },
    })


def _parse_cfn_timestamp(value: str) -> datetime:
    """Parse an RFC3339 CFN output; stdlib keeps at most microsecond precision."""
    if "." in value:
        head, frac = value.split(".", 1)
        value = f"{head}.{frac.rstrip('Z')[:6]}+00:00"
    else:
        value = value.replace("Z", "+00:00")
    return datetime.fromisoformat(value)


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation PortalProduct reads back through API Gateway V2 with Ref as its ARN,
    GetAtt attributes and every templated property matching an independent ListPortalProducts
    entry; deleting the stack removes it, which API Gateway V2 then refuses by id.
    """
    apigwv2 = ctx.client("apigatewayv2")
    cf = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-apigwv2pp-")
    display = ctx.unique_name("sim2real-apigwv2pp-disp-")

    stack_id = create_stack(ctx, cf, stack, _template(display, _DESCRIPTION))
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", f"stack {stack!r} ended {status!r}"
    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]
    want_arn = f"arn:{partition}:apigateway:{ctx.region}:{ctx.account}:/portalproducts/{out['ProductId']}"

    # Ref against an independent read (ListPortalProducts by the declared DisplayName), never a
    # read keyed by the Ref.
    matches = [p for p in paginate(apigwv2, "list_portal_products", "Items") if p["DisplayName"] == display]
    assert len(matches) == 1, f"ListPortalProducts found {matches!r} for DisplayName {display!r}"
    listed = matches[0]
    assert (out["ProductRef"], out["ProductArn"]) == (want_arn, want_arn), (
        f"Ref {out['ProductRef']!r} / GetAtt PortalProductArn {out['ProductArn']!r}, "
        f"expected {want_arn!r}"
    )
    assert listed["PortalProductArn"] == want_arn, (
        f"ListPortalProducts reports PortalProductArn {listed['PortalProductArn']!r}, "
        f"expected {want_arn!r}"
    )
    assert listed["PortalProductId"] == out["ProductId"], (
        f"ListPortalProducts reports PortalProductId {listed['PortalProductId']!r}, "
        f"GetAtt PortalProductId was {out['ProductId']!r}"
    )

    # Every templated property, through a direct GetPortalProduct by the GetAtt id.
    direct = apigwv2.get_portal_product(PortalProductId=out["ProductId"])
    got = {k: direct.get(k) for k in ("DisplayName", "Description", "PortalProductArn", "PortalProductId")}
    want = {
        "DisplayName": display, "Description": _DESCRIPTION,
        "PortalProductArn": want_arn, "PortalProductId": out["ProductId"],
    }
    assert got == want, f"GetPortalProduct returned {got!r}, expected {want!r}"
    assert _parse_cfn_timestamp(out["ProductLastModified"]) == direct["LastModified"].astimezone(timezone.utc), (
        f"GetAtt LastModified {out['ProductLastModified']!r} != GetPortalProduct's "
        f"{direct['LastModified'].isoformat()!r}"
    )
    own_tags = {k: v for k, v in direct.get("Tags", {}).items() if not k.startswith("aws:")}
    assert own_tags == {"sim2real": stack}, f"non-CloudFormation tags were {own_tags!r}"

    delete_stack(cf, stack_id)
    until_raises(lambda: apigwv2.get_portal_product(PortalProductId=out["ProductId"]))
    not_found = (
        "NotFoundException",
        f"Product not found in account {ctx.account} with id {out['ProductId']}",
    )
    expect_error(lambda: apigwv2.get_portal_product(PortalProductId=out["ProductId"]), *not_found)
    survivors = [p for p in paginate(apigwv2, "list_portal_products", "Items") if p["DisplayName"] == display]
    assert survivors == [], f"the deleted product is still listed: {survivors!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
