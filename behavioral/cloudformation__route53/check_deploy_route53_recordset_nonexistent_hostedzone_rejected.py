"""deploy-route53-recordset-nonexistent-hostedzone-rejected."""
from __future__ import annotations

import json
import re
import time

from behavioral_harness import tags

CHECK = "deploy-route53-recordset-nonexistent-hostedzone-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "route53"]

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

#: A hosted-zone-id-shaped string Route53 never assigns, so it is syntactically valid and
#: guaranteed absent.
_BOGUS_ZONE_ID = "Z0000000000000NOTREAL"
_REJECTED = (
    f"No hosted zone found with ID: {_BOGUS_ZONE_ID} "
    "(Service: Route53, Status Code: 404, Request ID: <id>) (SDK Attempt Count: <n>)",
    "InvalidRequest",
)


def _template(zone_name: str, rec_name: str, zone_id) -> str:
    """A hosted zone and a TXT record in it whose HostedZoneId is ``zone_id``."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Zone": {"Type": "AWS::Route53::HostedZone", "Properties": {"Name": zone_name}},
            "Rec": {
                "Type": "AWS::Route53::RecordSet",
                "Properties": {
                    "HostedZoneId": zone_id, "Name": rec_name, "Type": "TXT",
                    "TTL": "300", "ResourceRecords": ['"sim2real"'],
                },
            },
        },
        "Outputs": {"ZoneId": {"Value": {"Ref": "Zone"}}},
    })


def _zones_named(route53, zone_name: str) -> list:
    return [z["Id"] for z in route53.list_hosted_zones_by_name(
        DNSName=zone_name, MaxItems="1")["HostedZones"] if z["Name"] == zone_name]


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Route53::RecordSet naming a HostedZoneId Route53 never assigned fails
    with Route53's exact NoSuchHostedZone reason and the stack rolls back, leaving no hosted zone,
    while the same template with HostedZoneId set to its own zone deploys the record.

    Reference: https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html
    """
    route53 = ctx.client("route53")
    cfn = ctx.client("cloudformation")
    good_base = ctx.unique_name("sim2real-r53negrs-ok-")
    bad_base = ctx.unique_name("sim2real-r53negrs-bad-")

    # Positive control: the same template, HostedZoneId given the stack's own zone.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-r53negrs-"),
                           _template(f"{good_base}.test.", f"txt.{good_base}.test.",
                                     {"Ref": "Zone"}))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    zone_id = stack_outputs(cfn, good_id)["ZoneId"]
    records = [(rr["Type"], rr["TTL"], [r["Value"] for r in rr["ResourceRecords"]])
               for rr in paginate(route53, "list_resource_record_sets", "ResourceRecordSets",
                                  HostedZoneId=zone_id)
               if rr["Name"] == f"txt.{good_base}.test."]
    assert records == [("TXT", 300, ['"sim2real"'])], f"control record {records!r}"

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-r53negrs-"),
                          _template(f"{bad_base}.test.", f"txt.{bad_base}.test.", _BOGUS_ZONE_ID))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"rejected stack ended {status!r}"
    got = handler_reason(failed_reason(stack_events(cfn, bad_id), "Rec"), ctx.account)
    assert got == _REJECTED, f"handler reason {got!r}, expected {_REJECTED!r}"

    # Rollback absence through Route53, before any delete: the bad stack's zone (and with it any
    # record in it) is gone, while the control's zone is listed by the same read.
    assert _zones_named(route53, f"{bad_base}.test.") == [], "the rolled-back zone is listed"
    assert _zones_named(route53, f"{good_base}.test.") == [f"/hostedzone/{zone_id}"], (
        "the control zone is not listed"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
