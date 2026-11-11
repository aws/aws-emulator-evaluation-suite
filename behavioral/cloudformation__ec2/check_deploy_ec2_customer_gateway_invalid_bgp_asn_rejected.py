"""deploy-ec2-customer-gateway-invalid-bgp-asn-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-ec2-customer-gateway-invalid-bgp-asn-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "ec2"]

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

_CGW_IP = "203.0.113.5"  # TEST-NET-3, RFC 5737 documented example range
_GOOD_ASN = 65003
_BAD_ASN = 0

_REJECTED = (
    "Value (0) for parameter bgpAsn is invalid. Invalid Format. "
    "(Service: Ec2, Status Code: 400, Request ID: <id>) (SDK Attempt Count: <n>)",
    "GeneralServiceException",
)


def _template(bgp_asn: int) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Cgw": {"Type": "AWS::EC2::CustomerGateway", "Properties": {
                "Type": "ipsec.1", "IpAddress": _CGW_IP, "BgpAsn": bgp_asn,
            }},
        },
        "Outputs": {"CgwRef": {"Value": {"Ref": "Cgw"}}},
    })


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::EC2::CustomerGateway with BgpAsn 0 is refused by the EC2 handler and
    rolls back leaving no customer gateway, while the same template with a valid ASN deploys.
    """
    cf = ctx.client("cloudformation")
    ec2 = ctx.client("ec2")
    good_stack = ctx.unique_name("sim2real-ec2cgwasn-good-")
    bad_stack = ctx.unique_name("sim2real-ec2cgwasn-bad-")

    # Positive control: the SAME template, the one property given a VALID value (never dropped).
    good_id = create_stack(ctx, cf, good_stack, _template(_GOOD_ASN))
    status = wait_stack(cf, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    good_ref = stack_outputs(cf, good_id)["CgwRef"]
    good_cgws = ec2.describe_customer_gateways(
        Filters=[{"Name": "tag:sim2real", "Values": [good_stack]}]
    )["CustomerGateways"]
    got = [(c["CustomerGatewayId"], c["BgpAsn"], c["IpAddress"], c["Type"], c["State"])
           for c in good_cgws]
    assert got == [(good_ref, str(_GOOD_ASN), _CGW_IP, "ipsec.1", "available")], (
        f"control customer gateway reads {good_cgws!r}"
    )
    delete_stack(cf, good_id)

    bad_id = create_stack(ctx, cf, bad_stack, _template(_BAD_ASN))
    status = wait_stack(cf, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    rows = validation_rows(cf, bad_id)
    assert rows == [], f"refused by early validation, not by the handler: {rows!r}"
    reason = failed_reason(stack_events(cf, bad_id), "Cgw")
    got = handler_reason(reason, ctx.account, bad_stack)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through EC2, by the tag the gateway would have, BEFORE this check deletes.
    listed = ec2.describe_customer_gateways(
        Filters=[{"Name": "tag:sim2real", "Values": [bad_stack]}]
    )["CustomerGateways"]
    assert listed == [], f"the rolled-back customer gateway is listed: {listed!r}"

    delete_stack(cf, bad_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
