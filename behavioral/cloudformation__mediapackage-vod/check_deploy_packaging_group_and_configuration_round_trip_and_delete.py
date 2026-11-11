"""deploy-packaging-group-and-configuration-round-trip-and-delete."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-packaging-group-and-configuration-round-trip-and-delete"
GROUP = "deploy"
SERVICES = ["cloudformation", "mediapackage-vod"]

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


def _template(group_id: str, config_id: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Group": {
                "Type": "AWS::MediaPackage::PackagingGroup",
                "Properties": {"Id": group_id},
            },
            "Config": {
                "Type": "AWS::MediaPackage::PackagingConfiguration",
                "Properties": {
                    "Id": config_id,
                    "PackagingGroupId": {"Ref": "Group"},
                    "HlsPackage": {"HlsManifests": [{}]},
                },
            },
        },
        "Outputs": {
            "GroupId": {"Value": {"Ref": "Group"}},
            "GroupArn": {"Value": {"Fn::GetAtt": ["Group", "Arn"]}},
            "GroupDomainName": {"Value": {"Fn::GetAtt": ["Group", "DomainName"]}},
            "ConfigId": {"Value": {"Ref": "Config"}},
            "ConfigArn": {"Value": {"Fn::GetAtt": ["Config", "Arn"]}},
        },
    })


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation",
      "plane:control")
def run(ctx) -> None:
    """A CloudFormation PackagingGroup and PackagingConfiguration read back through MediaPackage
    VOD's own describe calls with the Ref identity, the GetAtt attributes and the declared HLS
    manifest; deleting the stack removes both resources for good.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-mediapackage-packaginggroup.html
    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-mediapackage-packagingconfiguration.html
    """
    mpvod = ctx.client("mediapackage-vod")
    cfn = ctx.client("cloudformation")
    stack = ctx.unique_name("sim2real-mpvodpg-")
    group_id = ctx.unique_name("sim2real-mpvodpg-group-")
    config_id = ctx.unique_name("sim2real-mpvodpg-config-")

    stack_id = create_stack(ctx, cfn, stack, _template(group_id, config_id))
    status = wait_stack(cfn, stack_id)
    assert status == "CREATE_COMPLETE", (
        f"stack {stack!r} ended {status!r}: {decisive_rows(stack_events(cfn, stack_id))!r}"
    )
    outputs = stack_outputs(cfn, stack_id)
    assert outputs["GroupId"] == group_id, (
        f"Group Ref {outputs['GroupId']!r} does not equal the declared Id {group_id!r}"
    )
    assert outputs["ConfigId"] == config_id, (
        f"Config Ref {outputs['ConfigId']!r} does not equal the declared Id {config_id!r}"
    )

    group = mpvod.describe_packaging_group(Id=group_id)
    assert group["Id"] == group_id, f"DescribePackagingGroup returned Id {group['Id']!r}"
    assert group["Arn"] == outputs["GroupArn"], (
        f"expected Group Arn {outputs['GroupArn']!r}, MediaPackage VOD reports {group['Arn']!r}"
    )
    assert group["DomainName"] == outputs["GroupDomainName"], (
        f"expected Group DomainName {outputs['GroupDomainName']!r}, MediaPackage VOD reports "
        f"{group['DomainName']!r}"
    )

    config = mpvod.describe_packaging_configuration(Id=config_id)
    assert config["Id"] == config_id, (
        f"DescribePackagingConfiguration returned Id {config['Id']!r}"
    )
    assert config["PackagingGroupId"] == group_id, (
        f"expected the configuration's PackagingGroupId to be {group_id!r}, MediaPackage VOD "
        f"reports {config['PackagingGroupId']!r}"
    )
    assert config["Arn"] == outputs["ConfigArn"], (
        f"expected Config Arn {outputs['ConfigArn']!r}, MediaPackage VOD reports {config['Arn']!r}"
    )
    assert len(config["HlsPackage"]["HlsManifests"]) == 1, (
        f"expected one HLS manifest, MediaPackage VOD reports "
        f"{config['HlsPackage']['HlsManifests']!r}"
    )

    delete_stack(cfn, stack_id)
    stack_gone = ("ValidationError", f"Stack with id {stack} does not exist")
    expect_error(lambda: cfn.describe_stacks(StackName=stack), *stack_gone)
    config_gone = ("NotFoundException", f"PackagingConfig with id={config_id} not found")
    expect_error(lambda: mpvod.describe_packaging_configuration(Id=config_id), *config_gone)
    group_gone = ("NotFoundException", f"PackagingGroup with id={group_id} not found")
    expect_error(lambda: mpvod.describe_packaging_group(Id=group_id), *group_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
