"""deploy-origin-access-control-invalid-signing-protocol-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "deploy-origin-access-control-invalid-signing-protocol-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "cloudfront"]

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


# ---- Check-specific: the template, then run(). ----

_VALID_SIGNING_PROTOCOL = "sigv4"
_INVALID_SIGNING_PROTOCOL = "sim2real-bogus-protocol"
_VALIDATION = (
    "OAC", "PROPERTY_VALIDATION", "FAILED", "FAIL",
    f"Property value [{_INVALID_SIGNING_PROTOCOL}] does not match pattern: ^(sigv4|sigv4a)$",
    "/Resources/OAC/Properties/OriginAccessControlConfig/SigningProtocol",
)
_STACK_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues "
    "with resource and property details, resolve each error, then retry the operation."
)


def _oac_config(name: str, signing_protocol: str) -> dict:
    return {
        "Name": name,
        "OriginAccessControlOriginType": "s3",
        "SigningBehavior": "always",
        "SigningProtocol": signing_protocol,
    }


def _template(name: str, signing_protocol: str) -> str:
    return json.dumps({
        "Resources": {"OAC": {"Type": "AWS::CloudFront::OriginAccessControl", "Properties": {
            "OriginAccessControlConfig": _oac_config(name, signing_protocol)}}},
        "Outputs": {"OacId": {"Value": {"Ref": "OAC"}}},
    })


def _oacs_named(cf, name: str) -> list[dict]:
    """Every origin access control named ``name``, across all Marker pages."""
    found, marker = [], None
    while True:
        page = cf.list_origin_access_controls(**({"Marker": marker} if marker else {}))
        page = page["OriginAccessControlList"]
        found += [item for item in page.get("Items", []) if item["Name"] == name]
        marker = page.get("NextMarker")
        if not marker:
            return found


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A CloudFormation OriginAccessControl with a SigningProtocol outside its pattern fails validation.

    The early-validation row names the property path and reason, and no control of that name
    exists, while the same template with sigv4 deploys and reads back its whole configuration.
    """
    cfn = ctx.client("cloudformation")
    cf = ctx.client("cloudfront")
    good_name = ctx.unique_name("sim2real-cf-oacgood-")
    bad_name = ctx.unique_name("sim2real-cf-oacbad-")

    # Positive control: the same template, SigningProtocol given its valid value.
    good_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cf-oacgood-"),
                           _template(good_name, _VALID_SIGNING_PROTOCOL))
    status = wait_stack(cfn, good_id)
    assert status == "CREATE_COMPLETE", f"control stack ended {status!r}"
    oac_id = stack_outputs(cfn, good_id)["OacId"]
    listed = [o["Id"] for o in _oacs_named(cf, good_name)]
    assert listed == [oac_id], f"origin access controls named {good_name!r}: {listed!r}"
    got = cf.get_origin_access_control(Id=oac_id)["OriginAccessControl"]["OriginAccessControlConfig"]
    want = _oac_config(good_name, _VALID_SIGNING_PROTOCOL)
    assert {k: got.get(k) for k in want} == want, f"control OAC config {got!r}"

    bad_id = create_stack(ctx, cfn, ctx.unique_name("sim2real-cf-oacbad-"),
                          _template(bad_name, _INVALID_SIGNING_PROTOCOL))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", f"invalid-protocol stack ended {status!r}"
    rows = validation_rows(cfn, bad_id)
    assert rows == [_VALIDATION], f"validation rows {rows!r}, expected {[_VALIDATION]!r}"
    failed = [(e["LogicalResourceId"], e.get("ResourceStatusReason"))
              for e in stack_events(cfn, bad_id) if e["ResourceStatus"] == "CREATE_FAILED"]
    assert failed == [(failed[0][0], _STACK_REASON)] and failed[0][0] != "OAC", (
        f"CREATE_FAILED rows {failed!r}: only the stack's validation failure, never the OAC"
    )
    left = _oacs_named(cf, bad_name)
    assert left == [], f"an origin access control named {bad_name!r} exists: {left!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
