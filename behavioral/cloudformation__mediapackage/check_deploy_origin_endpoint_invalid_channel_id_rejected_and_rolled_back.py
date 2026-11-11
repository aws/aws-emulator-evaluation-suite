"""deploy-origin-endpoint-invalid-channel-id-rejected-and-rolled-back."""
from __future__ import annotations

import json
import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-origin-endpoint-invalid-channel-id-rejected-and-rolled-back"
GROUP = "deploy"
SERVICES = ["cloudformation", "mediapackage"]

# ---- CloudFormation helpers: copy VERBATIM; delete the ones the check never calls. ----

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

#: The endpoint serves only a documentation range (RFC 5737), so its URL is never open.
_ALLOWED_CIDRS = ["192.0.2.0/24"]


def _bad_template(endpoint_id: str, missing_channel_id: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Endpoint": {
                "Type": "AWS::MediaPackage::OriginEndpoint",
                "Properties": {
                    "Id": endpoint_id,
                    "ChannelId": missing_channel_id,
                    "ManifestName": "index",
                    "HlsPackage": {"PlaylistType": "EVENT"},
                    "Whitelist": _ALLOWED_CIDRS,
                },
            },
        },
    })


def _good_template(channel_id: str, endpoint_id: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Channel": {
                "Type": "AWS::MediaPackage::Channel",
                "Properties": {"Id": channel_id},
            },
            "Endpoint": {
                "Type": "AWS::MediaPackage::OriginEndpoint",
                "Properties": {
                    "Id": endpoint_id,
                    "ChannelId": {"Ref": "Channel"},
                    "ManifestName": "index",
                    "HlsPackage": {"PlaylistType": "EVENT"},
                    "Whitelist": _ALLOWED_CIDRS,
                },
            },
        },
    })


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::MediaPackage::OriginEndpoint whose ChannelId names no channel
    fails with CloudFormation's NotFound for that channel, the stack rolls back and MediaPackage
    holds no endpoint; the same endpoint given a channel that exists succeeds.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-mediapackage-originendpoint.html
    """
    mp = ctx.client("mediapackage")
    cfn = ctx.client("cloudformation")
    bad_stack = ctx.unique_name("sim2real-mpepbad-")
    endpoint_id = ctx.unique_name("sim2real-mpepbad-endpoint-")
    missing_channel_id = ctx.unique_name("sim2real-mpepbad-missing-channel-")

    bad_id = create_stack(ctx, cfn, bad_stack, _bad_template(endpoint_id, missing_channel_id))
    status = wait_stack(cfn, bad_id)
    assert status == "ROLLBACK_COMPLETE", (
        f"stack {bad_stack!r} ended {status!r}, expected ROLLBACK_COMPLETE"
    )

    parsed = handler_reason(failed_reason(stack_events(cfn, bad_id), "Endpoint"), ctx.account)
    want = (
        f"Resource of type 'AWS::MediaPackage::Channel' with identifier "
        f"'{missing_channel_id}' was not found.",
        "NotFound",
    )
    assert parsed == want, f"expected {want!r}, got {parsed!r}"

    endpoint_absent = ("NotFoundException", f"originEndpoint with id={endpoint_id} not found")
    expect_error(lambda: mp.describe_origin_endpoint(Id=endpoint_id), *endpoint_absent)

    # Positive control: the identical mechanism, given a channel that exists, succeeds.
    good_stack = ctx.unique_name("sim2real-mpepgood-")
    good_channel_id = ctx.unique_name("sim2real-mpepgood-channel-")
    good_endpoint_id = ctx.unique_name("sim2real-mpepgood-endpoint-")
    good_id = create_stack(ctx, cfn, good_stack, _good_template(good_channel_id, good_endpoint_id))
    good_status = wait_stack(cfn, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack {good_stack!r} ended {good_status!r}: "
        f"{decisive_rows(stack_events(cfn, good_id))!r}"
    )
    control = mp.describe_origin_endpoint(Id=good_endpoint_id)
    assert control["ChannelId"] == good_channel_id, (
        f"expected the control endpoint's ChannelId to be {good_channel_id!r}, MediaPackage "
        f"reports {control['ChannelId']!r}"
    )
    got = (control["ManifestName"], control["HlsPackage"]["PlaylistType"], control["Whitelist"])
    assert got == ("index", "EVENT", _ALLOWED_CIDRS), (
        f"expected the control's (ManifestName, PlaylistType, allowed CIDRs) "
        f"{('index', 'EVENT', _ALLOWED_CIDRS)!r}, MediaPackage reports {got!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
