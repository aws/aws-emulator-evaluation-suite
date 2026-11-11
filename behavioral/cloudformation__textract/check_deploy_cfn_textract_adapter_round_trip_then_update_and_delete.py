"""deploy-cfn-textract-adapter-round-trip-then-update-and-delete."""
from __future__ import annotations

import json
import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-cfn-textract-adapter-round-trip-then-update-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "textract"]

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

_NOT_FOUND = ("ResourceNotFoundException", "Adapter Id not found.")


def _template(adapter_name, description, auto_update, adapter_tag_value):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Adapter": {
                "Type": "AWS::Textract::Adapter",
                "Properties": {
                    "AdapterName": adapter_name,
                    "FeatureTypes": ["QUERIES"],
                    "AutoUpdate": auto_update,
                    "Description": description,
                    "Tags": [{"Key": "sim2real-adapter", "Value": adapter_tag_value}],
                },
            }
        },
        "Outputs": {
            "AdapterRef": {"Value": {"Ref": "Adapter"}},
            "AdapterArn": {"Value": {"Fn::GetAtt": ["Adapter", "Arn"]}},
            "AdapterId": {"Value": {"Fn::GetAtt": ["Adapter", "AdapterId"]}},
            "AdapterCreationTime": {"Value": {"Fn::GetAtt": ["Adapter", "CreationTime"]}},
        },
    })


def _parse_cfn_time(value):
    """A GetAtt CreationTime string ("...Z") as an aware UTC datetime."""
    return datetime.strptime(value, "%Y-%m-%dT%H:%M:%S.%fZ").replace(tzinfo=timezone.utc)


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CloudFormation Textract adapter round-trips through Textract, then updates in place.

    Ref, the read-only GetAtt attributes and every templated property match Textract's own
    values; an in-place update keeps the same adapter, and deleting the stack removes it.
    """
    cf = ctx.client("cloudformation")
    textract = ctx.client("textract")
    stack = ctx.unique_name("sim2real-cfn-ta-")
    adapter_name = ctx.unique_name("sim2real-cfn-ta-adapter-")

    stack_id = create_stack(
        ctx, cf, stack, _template(adapter_name, "v1 description", "DISABLED", "v1")
    )
    status = wait_stack(cf, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    out = stack_outputs(cf, stack_id)
    partition = stack_id.split(":")[1]
    adapter_id = out["AdapterId"]
    expected_arn = f"arn:{partition}:textract:{ctx.region}:{ctx.account}:/adapters/{adapter_id}"

    # Ref == primary identifier (Arn) against the documented ARN format: GetAdapter has no Arn
    # field to read it back from, so the ARN's functional correctness is proven below instead.
    assert (out["AdapterRef"], out["AdapterArn"]) == (expected_arn, expected_arn), (
        f"Ref {out['AdapterRef']!r}, GetAtt Arn {out['AdapterArn']!r}, expected {expected_arn!r}"
    )

    listed = [a["AdapterId"] for a in paginate(textract, "list_adapters", "Adapters")
              if a["AdapterName"] == adapter_name]
    assert listed == [adapter_id], f"ListAdapters found {listed!r} for GetAtt {adapter_id!r}"
    created = textract.get_adapter(AdapterId=adapter_id)
    # Every templated property, read back through Textract.
    got = {
        "AdapterName": created["AdapterName"],
        "Description": created["Description"],
        "FeatureTypes": created["FeatureTypes"],
        "AutoUpdate": created["AutoUpdate"],
        "Tags": created["Tags"],
    }
    want = {
        "AdapterName": adapter_name,
        "Description": "v1 description",
        "FeatureTypes": ["QUERIES"],
        "AutoUpdate": "DISABLED",
        "Tags": {"sim2real": stack, "sim2real-adapter": "v1"},
    }
    assert got == want, f"GetAdapter after create reads {got!r}, expected {want!r}"
    # Read-only GetAtt CreationTime == the service's own value.
    cfn_created_at = _parse_cfn_time(out["AdapterCreationTime"])
    service_created_at = created["CreationTime"].astimezone(timezone.utc)
    assert cfn_created_at == service_created_at, (
        f"GetAtt CreationTime {cfn_created_at!r} != GetAdapter CreationTime {service_created_at!r}"
    )

    # The ARN is functionally correct: Textract itself accepts it as this adapter's identity.
    tags_by_arn = textract.list_tags_for_resource(ResourceARN=out["AdapterArn"])["Tags"]
    assert tags_by_arn == want["Tags"], (
        f"ListTagsForResource(ResourceARN=<GetAtt Arn>) reads {tags_by_arn!r}, expected tags "
        f"{want['Tags']!r}"
    )

    # Update mutable properties in place (FeatureTypes is create-only and stays QUERIES).
    cf.update_stack(
        StackName=stack_id,
        TemplateBody=_template(adapter_name, "v2 description", "ENABLED", "v2"),
    )
    status = wait_stack(cf, stack_id)
    assert status == "UPDATE_COMPLETE", (
        f"update ended {status!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )
    updated = textract.get_adapter(AdapterId=adapter_id)
    got_after = {
        "Description": updated["Description"],
        "AutoUpdate": updated["AutoUpdate"],
        "Tags": updated["Tags"],
    }
    want_after = {
        "Description": "v2 description",
        "AutoUpdate": "ENABLED",
        "Tags": {"sim2real": stack, "sim2real-adapter": "v2"},
    }
    assert got_after == want_after, f"GetAdapter after update reads {got_after!r}"
    # Same resource, updated rather than replaced: the server-minted CreationTime is unchanged.
    assert updated["CreationTime"] == created["CreationTime"], (
        f"CreationTime moved {created['CreationTime']!r} -> {updated['CreationTime']!r}, "
        "so the update replaced the adapter instead of updating it in place"
    )

    delete_stack(cf, stack_id)
    # Absence through Textract, by the AdapterId the adapter actually had: it could exist.
    expect_error(lambda: textract.get_adapter(AdapterId=adapter_id), *_NOT_FOUND)
    left = [a for a in paginate(textract, "list_adapters", "Adapters")
            if a["AdapterName"] == adapter_name]
    assert left == [], f"ListAdapters still lists {left!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
