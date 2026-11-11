"""deploy-location-map-and-apikey-restricted-to-map-round-trip-and-delete."""
from __future__ import annotations

import datetime
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-location-map-and-apikey-restricted-to-map-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "location"]

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

_STYLE = "VectorEsriStreets"
# A documentation-reserved referer, so the key serves no real site.
_REFERERS = ["https://example.com/*"]


def _template(map_name: str, key_name: str, tag_value: str, expire_time: str) -> str:
    t = [{"Key": "sim2real-check", "Value": tag_value}]
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Map": {
                "Type": "AWS::Location::Map",
                "Properties": {"MapName": map_name, "Configuration": {"Style": _STYLE},
                                "Tags": t},
            },
            "Key": {
                "Type": "AWS::Location::APIKey",
                "Properties": {
                    "KeyName": key_name,
                    "ExpireTime": expire_time,
                    "ForceDelete": True,
                    "Restrictions": {
                        "AllowActions": ["geo:GetMap*"],
                        "AllowResources": [{"Fn::GetAtt": ["Map", "Arn"]}],
                        "AllowReferers": _REFERERS,
                    },
                    "Tags": t,
                },
            },
        },
        "Outputs": {
            "MapName": {"Value": {"Ref": "Map"}},
            "MapArn": {"Value": {"Fn::GetAtt": ["Map", "Arn"]}},
            "KeyName": {"Value": {"Ref": "Key"}},
            "KeyArn": {"Value": {"Fn::GetAtt": ["Key", "KeyArn"]}},
        },
    })


def _tags_of(loc, arn: str) -> dict:
    """The resource's tags at Location, without CloudFormation's own aws: system tags."""
    found = loc.list_tags_for_resource(ResourceArn=arn)["Tags"]
    return {k: v for k, v in found.items() if not k.startswith("aws:")}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation AWS::Location::Map and an expiring AWS::Location::APIKey restricted to
    its ARN and a referer read back through Location with the declared Style, restrictions,
    ExpireTime and tags, and both are removed on delete.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-location-apikey.html
    """
    loc = ctx.client("location")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-locmapkey-")
    map_name = ctx.unique_name("sim2real-loc-map-")
    key_name = ctx.unique_name("sim2real-loc-key-")
    # A key that expires a day out, never one that lives forever.
    expire_at = (datetime.datetime.now(datetime.UTC).replace(microsecond=0)
                 + datetime.timedelta(days=1))
    expire_time = expire_at.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    stack_id = create_stack(ctx, cfn, stack, _template(map_name, key_name, CHECK, expire_time))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    want_tags = {"sim2real": stack, "sim2real-check": CHECK}
    assert outputs["MapName"] == map_name, (
        f"expected Ref on the Map to equal {map_name!r}, stack reports {outputs['MapName']!r}"
    )
    assert outputs["KeyName"] == key_name, (
        f"expected Ref on the Key to equal {key_name!r}, stack reports {outputs['KeyName']!r}"
    )

    gmap = loc.describe_map(MapName=map_name)
    assert gmap["MapArn"] == outputs["MapArn"], (
        f"expected DescribeMap MapArn to equal the stack's GetAtt {outputs['MapArn']!r}, "
        f"Location reports {gmap['MapArn']!r}"
    )
    assert gmap["Configuration"]["Style"] == _STYLE, (
        f"expected the declared Style {_STYLE!r}, Location reports {gmap['Configuration']['Style']!r}"
    )
    map_tags = _tags_of(loc, gmap["MapArn"])
    assert map_tags == want_tags, (
        f"expected the Map's stack and declared tags {want_tags!r}, Location reports {map_tags!r}"
    )

    key = loc.describe_key(KeyName=key_name)
    assert key["KeyArn"] == outputs["KeyArn"], (
        f"expected DescribeKey KeyArn to equal the stack's GetAtt {outputs['KeyArn']!r}, "
        f"Location reports {key['KeyArn']!r}"
    )
    assert key["Restrictions"]["AllowActions"] == ["geo:GetMap*"], (
        f"expected the declared AllowActions ['geo:GetMap*'], Location reports "
        f"{key['Restrictions']['AllowActions']!r}"
    )
    assert key["Restrictions"]["AllowResources"] == [outputs["MapArn"]], (
        f"expected the declared AllowResources [{outputs['MapArn']!r}], Location reports "
        f"{key['Restrictions']['AllowResources']!r}"
    )
    assert key["Restrictions"].get("AllowReferers") == _REFERERS, (
        f"expected the declared AllowReferers {_REFERERS!r}, Location reports "
        f"{key['Restrictions'].get('AllowReferers')!r}"
    )
    assert key["ExpireTime"] == expire_at, (
        f"expected the declared ExpireTime {expire_at.isoformat()}, Location reports "
        f"{key['ExpireTime']!r}"
    )
    key_tags = _tags_of(loc, key["KeyArn"])
    assert key_tags == want_tags, (
        f"expected the Key's stack and declared tags {want_tags!r}, Location reports {key_tags!r}"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)
    map_gone = ("ResourceNotFoundException", f"Map not found: {map_name}.")
    expect_error(lambda: loc.describe_map(MapName=map_name), *map_gone)
    key_gone = ("ResourceNotFoundException", f"Api key not found: {key_name}.")
    expect_error(lambda: loc.describe_key(KeyName=key_name), *key_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
