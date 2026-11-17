"""false-condition-skips-importvalue-of-missing-export."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "false-condition-skips-importvalue-of-missing-export"
GROUP = "conditions"
SERVICES = ["cloudformation"]

_CREATE_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
}


def _template(select_import_branch: str, *, safe_name: str, import_name: str, export_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "SelectImportBranch": {
                    "Type": "String",
                    "AllowedValues": ["true", "false"],
                    "Default": select_import_branch,
                }
            },
            "Conditions": {
                "UseImportBranch": {"Fn::Equals": [{"Ref": "SelectImportBranch"}, "true"]}
            },
            "Resources": {
                "SafeParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {"Name": safe_name, "Type": "String", "Value": "ok"},
                },
                "ImportParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Condition": "UseImportBranch",
                    "Properties": {
                        "Name": import_name,
                        "Type": "String",
                        "Value": {"Fn::ImportValue": export_name},
                    },
                },
            },
        }
    )


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A resource gated by a false Condition is never evaluated, so its Fn::ImportValue of a
    missing export does not block CreateStack; the same resource under a true Condition rolls
    CreateStack back naming the missing export, before any resource is created.
    """
    cfn = ctx.client("cloudformation")

    missing_export = ctx.unique_name("sim2real-cfn-condimp-no-such-export-")

    # --- Beat 1: the branch importing the missing export is NOT selected -------------------------
    skip_stack = ctx.unique_name("sim2real-cfn-condimp-skip-")
    skip_safe_name = ctx.unique_name("sim2real-cfn-condimp-skip-safe-")
    skip_import_name = ctx.unique_name("sim2real-cfn-condimp-skip-import-")
    cfn.create_stack(
        StackName=skip_stack,
        TemplateBody=_template(
            "false", safe_name=skip_safe_name, import_name=skip_import_name, export_name=missing_export
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, skip_stack))
    skip_status = _poll_stack(cfn, skip_stack)
    assert skip_status == "CREATE_COMPLETE", (
        f"the stack whose import branch is unselected must reach CREATE_COMPLETE, got {skip_status!r}"
    )
    skip_resources = {
        r["LogicalResourceId"]: r["ResourceStatus"]
        for r in cfn.describe_stack_resources(StackName=skip_stack)["StackResources"]
    }
    assert skip_resources == {"SafeParam": "CREATE_COMPLETE"}, (
        f"only the unconditional resource must exist; ImportParam's Condition is false and it "
        f"must never be created, got {skip_resources!r}"
    )

    # --- Beat 2: the same resource, Condition now true, fails naming the missing export ----------
    fail_stack = ctx.unique_name("sim2real-cfn-condimp-fail-")
    fail_safe_name = ctx.unique_name("sim2real-cfn-condimp-fail-safe-")
    fail_import_name = ctx.unique_name("sim2real-cfn-condimp-fail-import-")
    cfn.create_stack(
        StackName=fail_stack,
        TemplateBody=_template(
            "true", safe_name=fail_safe_name, import_name=fail_import_name, export_name=missing_export
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, fail_stack))
    fail_status = _poll_stack(cfn, fail_stack)
    assert fail_status == "ROLLBACK_COMPLETE", (
        f"the stack whose import branch IS selected and imports a missing export must roll back, "
        f"got {fail_status!r}"
    )

    events = []
    for page in cfn.get_paginator("describe_stack_events").paginate(StackName=fail_stack):
        events.extend(page["StackEvents"])
    expected_reason = f"No export named {missing_export} found. Rollback requested by user."
    matching = [
        e for e in events
        if e["LogicalResourceId"] == fail_stack
        and e["ResourceStatus"] == "ROLLBACK_IN_PROGRESS"
        and e.get("ResourceStatusReason") == expected_reason
    ]
    assert matching, (
        f"expected a ROLLBACK_IN_PROGRESS stack event whose reason is exactly {expected_reason!r}, "
        f"got {[(e['LogicalResourceId'], e['ResourceStatus'], e.get('ResourceStatusReason')) for e in events]!r}"
    )

    # CloudFormation resolves every in-scope resource's Fn::ImportValue before creating any of
    # them, so the whole stack rolls back and neither resource -- including the unconditional
    # SafeParam -- was ever created.
    fail_resources = cfn.describe_stack_resources(StackName=fail_stack)["StackResources"]
    assert fail_resources == [], (
        f"a stack that rolled back before resource processing began must list no resources, "
        f"got {fail_resources!r}"
    )


def _poll_stack(cfn, stack_name: str, timeout_s: float = 240.0, interval_s: float = 4.0) -> str:
    """Poll DescribeStacks to a create-terminal state; return the final StackStatus. RAISES on timeout."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in _CREATE_TERMINAL:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name!r} did not reach a create-terminal state within {timeout_s}s (last={last!r})")


def _delete_stack(cfn, stack_name: str) -> None:
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ValidationError":
            raise
        if "does not exist" not in exc.response["Error"].get("Message", ""):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
