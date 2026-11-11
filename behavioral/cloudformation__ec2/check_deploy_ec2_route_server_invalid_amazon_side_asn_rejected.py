"""deploy-ec2-route-server-invalid-amazon-side-asn-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-ec2-route-server-invalid-amazon-side-asn-rejected"
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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


# AmazonSideAsn's documented range is 1-4294967294; 0 sits just below it and is always refused.
_INVALID_ASN = 0
_VALID_ASN = 64512


def _template(tag_value: str, amazon_side_asn: int) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "RouteServer": {
                "Type": "AWS::EC2::RouteServer",
                "Properties": {"AmazonSideAsn": amazon_side_asn,
                               "Tags": [{"Key": "sim2real-res", "Value": tag_value}]},
            },
        },
        "Outputs": {
            "RouteServerId": {"Value": {"Ref": "RouteServer"}},
            "RouteServerArn": {"Value": {"Fn::GetAtt": ["RouteServer", "Arn"]}},
        },
    })


def _tagged(ec2, tag_value: str) -> list[dict]:
    return paginate(ec2, "describe_route_servers", "RouteServers",
                    Filters=[{"Name": "tag:sim2real-res", "Values": [tag_value]}])


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation route server with AmazonSideAsn below the schema minimum is refused.

    Early validation names the property, the stack rolls back and EC2 holds no route server
    with the template's tag, while the same template with a valid ASN deploys and reads back.
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")

    # Positive control: the same template with a valid ASN.
    good_tag = ctx.unique_name("sim2real-cfnrsasn-good-")
    good_id = create_stack(ctx, cfn, good_tag, _template(good_tag, _VALID_ASN))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"positive control stack ended {status!r}"
    out = stack_outputs(cfn, good_id)
    tagged = _tagged(ec2, good_tag)
    assert [r["RouteServerId"] for r in tagged] == [out["RouteServerId"]], (
        f"route servers tagged {good_tag!r}: {tagged!r}, Ref {out['RouteServerId']!r}"
    )
    partition = good_id.split(":")[1]
    want_arn = f"arn:{partition}:ec2:{ctx.region}:{ctx.account}:route-server/{out['RouteServerId']}"
    assert out["RouteServerArn"] == want_arn, f"GetAtt Arn {out['RouteServerArn']!r}"
    assert tagged[0]["AmazonSideAsn"] == _VALID_ASN, f"control route server {tagged[0]!r}"

    # Negative: only AmazonSideAsn changes, to a value below the schema minimum of 1.
    bad_tag = ctx.unique_name("sim2real-cfnrsasn-bad-")
    bad_id = create_stack(ctx, cfn, bad_tag, _template(bad_tag, _INVALID_ASN))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"negative stack ended {status!r}"
    rows = [r for r in validation_rows(cfn, bad_id) if r[3] == "FAIL"]
    want = [("RouteServer", "PROPERTY_VALIDATION", "FAILED", "FAIL",
             f"#/AmazonSideAsn: {_INVALID_ASN} is not greater or equal to 1",
             "/Resources/RouteServer/Properties/AmazonSideAsn")]
    assert rows == want, f"validation rows {rows!r}, expected {want!r}"

    # The rejected template never reached EC2: no route server carries its tag.
    tagged = _tagged(ec2, bad_tag)
    assert tagged == [], f"a route server tagged {bad_tag!r} exists: {tagged!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
