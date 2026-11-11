"""deploy-s3-storage-lens-and-group-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-s3-storage-lens-and-group-lifecycle"
GROUP = "deploy"
SERVICES = ["cloudformation", "s3control"]

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

_NOT_FOUND = ("NoSuchConfiguration", "The specified configuration does not exist.")


def _list_all(call, key, **kw):
    """Every item under ``key`` across all NextToken pages (S3 Control ships no paginator)."""
    items, token = [], None
    while True:
        page = call(**kw, **({"NextToken": token} if token else {}))
        items += page.get(key, [])
        token = page.get("NextToken")
        if not token:
            return items


@tags("axis:happy-path", "cap:c1", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CloudFormation-deployed AWS::S3::StorageLens and AWS::S3::StorageLensGroup resources are
    real at S3 Control: their Refs are the config id and group name, the GetAtt ARNs and the
    properties the template set read back verbatim, and the stack delete removes both."""
    cf = ctx.client("cloudformation")
    s3c = ctx.client("s3control")
    account = ctx.account
    stack_name = ctx.unique_name("sim2real-behav-cfn-sl-")
    sl_id = ctx.unique_name("sim2real-behav-cfn-sl-").lower()[:63]
    slg_name = ctx.unique_name("sim2real-behav-cfn-slg-").lower()[:63]

    template = json.dumps({
        "Resources": {
            "SL": {
                "Type": "AWS::S3::StorageLens",
                "Properties": {
                    "StorageLensConfiguration": {
                        "Id": sl_id,
                        "IsEnabled": True,
                        "AccountLevel": {"BucketLevel": {}},
                    }
                },
            },
            "SLG": {
                "Type": "AWS::S3::StorageLensGroup",
                "Properties": {
                    "Name": slg_name,
                    "Filter": {"MatchAnyPrefix": ["sim2real-data/"]},
                },
            },
        },
        "Outputs": {
            "SLRef": {"Value": {"Ref": "SL"}},
            "SLArn": {"Value": {"Fn::GetAtt": ["SL", "StorageLensConfiguration.StorageLensArn"]}},
            "SLGRef": {"Value": {"Ref": "SLG"}},
            "SLGArn": {"Value": {"Fn::GetAtt": ["SLG", "StorageLensGroupArn"]}},
        },
    })

    stack_id = create_stack(ctx, cf, stack_name, template)
    created = wait_stack(cf, stack_id)
    assert created == "CREATE_COMPLETE", (
        f"expected CREATE_COMPLETE, got {created!r}: {decisive_rows(stack_events(cf, stack_id))!r}"
    )

    outputs = stack_outputs(cf, stack_id)
    assert outputs["SLRef"] == sl_id, f"Ref of SL was {outputs['SLRef']!r}, expected {sl_id!r}"
    assert outputs["SLGRef"] == slg_name, f"Ref of SLG was {outputs['SLGRef']!r}, expected {slg_name!r}"
    partition = stack_id.split(":")[1]
    expected_sl_arn = f"arn:{partition}:s3:{ctx.region}:{account}:storage-lens/{sl_id}"
    expected_slg_arn = f"arn:{partition}:s3:{ctx.region}:{account}:storage-lens-group/{slg_name}"
    assert outputs["SLArn"] == expected_sl_arn, f"GetAtt StorageLensArn was {outputs['SLArn']!r}"
    assert outputs["SLGArn"] == expected_slg_arn, f"GetAtt StorageLensGroupArn was {outputs['SLGArn']!r}"

    # Refs against independent reads: S3 Control's own lists.
    listed_sl = [c["StorageLensArn"] for c in _list_all(
        s3c.list_storage_lens_configurations, "StorageLensConfigurationList", AccountId=account)
        if c["Id"] == sl_id]
    assert listed_sl == [expected_sl_arn], f"ListStorageLensConfigurations lists {listed_sl!r}"
    listed_slg = [g["StorageLensGroupArn"] for g in _list_all(
        s3c.list_storage_lens_groups, "StorageLensGroupList", AccountId=account)
        if g["Name"] == slg_name]
    assert listed_slg == [expected_slg_arn], f"ListStorageLensGroups lists {listed_slg!r}"

    # Independent reads at the owning service: S3 Control's own records.
    sl_got = s3c.get_storage_lens_configuration(ConfigId=sl_id, AccountId=account)
    sl_conf = sl_got["StorageLensConfiguration"]
    assert sl_conf["Id"] == sl_id, f"GetStorageLensConfiguration Id {sl_conf['Id']!r}"
    assert sl_conf["IsEnabled"] is True, f"GetStorageLensConfiguration IsEnabled {sl_conf['IsEnabled']!r}"
    assert sl_conf["AccountLevel"]["BucketLevel"] == {}, (
        f"GetStorageLensConfiguration AccountLevel.BucketLevel {sl_conf['AccountLevel']['BucketLevel']!r}"
    )
    assert sl_conf["StorageLensArn"] == expected_sl_arn, f"GetStorageLensConfiguration arn {sl_conf['StorageLensArn']!r}"

    slg_got = s3c.get_storage_lens_group(Name=slg_name, AccountId=account)
    slg_group = slg_got["StorageLensGroup"]
    assert slg_group["Name"] == slg_name, f"GetStorageLensGroup Name {slg_group['Name']!r}"
    assert slg_group["Filter"] == {"MatchAnyPrefix": ["sim2real-data/"]}, (
        f"GetStorageLensGroup Filter {slg_group['Filter']!r}"
    )
    assert slg_group["StorageLensGroupArn"] == expected_slg_arn, (
        f"GetStorageLensGroup arn {slg_group['StorageLensGroupArn']!r}"
    )

    delete_stack(cf, stack_id)

    until_raises(lambda: s3c.get_storage_lens_configuration(ConfigId=sl_id, AccountId=account), 60.0)
    expect_error(lambda: s3c.get_storage_lens_configuration(ConfigId=sl_id, AccountId=account),
                 *_NOT_FOUND)
    until_raises(lambda: s3c.get_storage_lens_group(Name=slg_name, AccountId=account), 60.0)
    expect_error(lambda: s3c.get_storage_lens_group(Name=slg_name, AccountId=account), *_NOT_FOUND)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
