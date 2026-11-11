"""deploy-channel-and-origin-endpoint-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-channel-and-origin-endpoint-round-trip-and-delete"
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

_MANIFEST_NAME = "index"
_PLAYLIST_TYPE = "EVENT"
_DESCRIPTION = "sim2real round trip"
#: The endpoint serves only a documentation range (RFC 5737), so its URL is never open.
_ALLOWED_CIDRS = ["192.0.2.0/24"]


def _template(channel_id: str, endpoint_id: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Channel": {
                "Type": "AWS::MediaPackage::Channel",
                "Properties": {"Id": channel_id, "Description": _DESCRIPTION},
            },
            "Endpoint": {
                "Type": "AWS::MediaPackage::OriginEndpoint",
                "Properties": {
                    "Id": endpoint_id,
                    "ChannelId": {"Ref": "Channel"},
                    "ManifestName": _MANIFEST_NAME,
                    "HlsPackage": {"PlaylistType": _PLAYLIST_TYPE},
                    "Whitelist": _ALLOWED_CIDRS,
                },
            },
        },
        "Outputs": {
            "ChannelId": {"Value": {"Ref": "Channel"}},
            "ChannelArn": {"Value": {"Fn::GetAtt": ["Channel", "Arn"]}},
            "EndpointId": {"Value": {"Ref": "Endpoint"}},
            "EndpointArn": {"Value": {"Fn::GetAtt": ["Endpoint", "Arn"]}},
            "EndpointUrl": {"Value": {"Fn::GetAtt": ["Endpoint", "Url"]}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation Channel and OriginEndpoint read back through MediaPackage's own
    DescribeChannel and DescribeOriginEndpoint with the Ref identity, the GetAtt attributes
    and the declared properties; deleting the stack removes both resources for good.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-mediapackage-channel.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-mediapackage-originendpoint.html
    """
    mp = ctx.client("mediapackage")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-mpch-")
    channel_id = ctx.unique_name("sim2real-mpch-channel-")
    endpoint_id = ctx.unique_name("sim2real-mpch-endpoint-")

    stack_id = create_stack(ctx, cfn, stack, _template(channel_id, endpoint_id))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    assert outputs["ChannelId"] == channel_id, (
        f"Channel Ref {outputs['ChannelId']!r} does not equal the declared Id {channel_id!r}"
    )
    assert outputs["EndpointId"] == endpoint_id, (
        f"Endpoint Ref {outputs['EndpointId']!r} does not equal the declared Id {endpoint_id!r}"
    )

    channel = mp.describe_channel(Id=channel_id)
    assert channel["Id"] == channel_id, f"DescribeChannel returned Id {channel['Id']!r}"
    assert channel["Arn"] == outputs["ChannelArn"], (
        f"expected Channel Arn {outputs['ChannelArn']!r}, MediaPackage reports {channel['Arn']!r}"
    )
    assert channel["Description"] == _DESCRIPTION, (
        f"expected Channel Description {_DESCRIPTION!r}, MediaPackage reports {channel.get('Description')!r}"
    )

    endpoint = mp.describe_origin_endpoint(Id=endpoint_id)
    assert endpoint["Id"] == endpoint_id, f"DescribeOriginEndpoint returned Id {endpoint['Id']!r}"
    assert endpoint["ChannelId"] == channel_id, (
        f"expected the endpoint's ChannelId to be {channel_id!r}, MediaPackage reports "
        f"{endpoint['ChannelId']!r}"
    )
    assert endpoint["Arn"] == outputs["EndpointArn"], (
        f"expected Endpoint Arn {outputs['EndpointArn']!r}, MediaPackage reports {endpoint['Arn']!r}"
    )
    assert endpoint["Url"] == outputs["EndpointUrl"], (
        f"expected Endpoint Url {outputs['EndpointUrl']!r}, MediaPackage reports {endpoint['Url']!r}"
    )
    assert endpoint["ManifestName"] == _MANIFEST_NAME, (
        f"expected ManifestName {_MANIFEST_NAME!r}, MediaPackage reports {endpoint['ManifestName']!r}"
    )
    assert endpoint["HlsPackage"]["PlaylistType"] == _PLAYLIST_TYPE, (
        f"expected HlsPackage.PlaylistType {_PLAYLIST_TYPE!r}, MediaPackage reports "
        f"{endpoint['HlsPackage']['PlaylistType']!r}"
    )
    assert endpoint["Whitelist"] == _ALLOWED_CIDRS, (
        f"expected allowed CIDRs {_ALLOWED_CIDRS!r}, MediaPackage reports {endpoint.get('Whitelist')!r}"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)
    endpoint_gone = ("NotFoundException", f"originEndpoint with id={endpoint_id} not found")
    expect_error(lambda: mp.describe_origin_endpoint(Id=endpoint_id), *endpoint_gone)
    channel_gone = ("NotFoundException", f"channel with id={channel_id} not found")
    expect_error(lambda: mp.describe_channel(Id=channel_id), *channel_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
