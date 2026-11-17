"""fn-if-unselected-branch-importvalue-of-missing-export-not-resolved."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fn-if-unselected-branch-importvalue-of-missing-export-not-resolved"
GROUP = "conditions"
SERVICES = ["cloudformation", "ssm"]

_CREATE_TERMINAL = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
}


def _template(select_branch: str, *, always_name: str, gated_name: str, export_name: str) -> str:
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "SelectBranch": {
                    "Type": "String",
                    "AllowedValues": ["true", "false"],
                    "Default": select_branch,
                }
            },
            "Conditions": {
                "UseImportBranch": {"Fn::Equals": [{"Ref": "SelectBranch"}, "true"]}
            },
            "Resources": {
                "AlwaysParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": always_name,
                        "Type": "String",
                        "Value": {
                            "Fn::If": [
                                "UseImportBranch",
                                {"Fn::ImportValue": export_name},
                                "safe-value",
                            ]
                        },
                    },
                },
                "GatedParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Condition": "UseImportBranch",
                    "Properties": {
                        "Name": gated_name,
                        "Type": "String",
                        "Value": {"Fn::ImportValue": export_name},
                    },
                },
            },
        }
    )


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """A false Condition means Fn::If never selects the branch holding Fn::ImportValue of a
    missing export, so the resource reaches CREATE_COMPLETE with the other branch's value; the
    same branch, once selected by a true Condition, fails CreateStack naming the missing export.
    """
    cfn = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    missing_export = ctx.unique_name("sim2real-cfn-fnif-no-such-export-")

    # --- Beat 1: condition false -> Fn::If selects the branch without the import -----------------
    ok_stack = ctx.unique_name("sim2real-cfn-fnif-ok-")
    ok_always_name = ctx.unique_name("sim2real-cfn-fnif-ok-always-")
    ok_gated_name = ctx.unique_name("sim2real-cfn-fnif-ok-gated-")
    cfn.create_stack(
        StackName=ok_stack,
        TemplateBody=_template(
            "false", always_name=ok_always_name, gated_name=ok_gated_name, export_name=missing_export
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, ok_stack))
    ok_status = _poll_stack(cfn, ok_stack)
    assert ok_status == "CREATE_COMPLETE", (
        f"a false Condition must leave Fn::If's missing-export branch unselected and unresolved, "
        f"reaching CREATE_COMPLETE, got {ok_status!r}"
    )

    ok_resources = {
        r["LogicalResourceId"]: r["ResourceStatus"]
        for r in cfn.describe_stack_resources(StackName=ok_stack)["StackResources"]
    }
    assert ok_resources == {"AlwaysParam": "CREATE_COMPLETE"}, (
        f"only the unconditional AlwaysParam must exist; GatedParam's Condition is false and it "
        f"must never be created, got {ok_resources!r}"
    )

    always_value = ssm.get_parameter(Name=ok_always_name)["Parameter"]["Value"]
    assert always_value == "safe-value", (
        f"Fn::If's false branch must be the value used when the Condition is false, "
        f"got {always_value!r}"
    )

    # --- Beat 2: condition true -> Fn::If now selects the branch importing the missing export ----
    fail_stack = ctx.unique_name("sim2real-cfn-fnif-fail-")
    fail_always_name = ctx.unique_name("sim2real-cfn-fnif-fail-always-")
    fail_gated_name = ctx.unique_name("sim2real-cfn-fnif-fail-gated-")
    cfn.create_stack(
        StackName=fail_stack,
        TemplateBody=_template(
            "true", always_name=fail_always_name, gated_name=fail_gated_name, export_name=missing_export
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, fail_stack))
    fail_status = _poll_stack(cfn, fail_stack)
    assert fail_status == "ROLLBACK_COMPLETE", (
        f"a true Condition must make Fn::If select the branch that imports the missing export, "
        f"rolling the stack back, got {fail_status!r}"
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

    fail_resources = cfn.describe_stack_resources(StackName=fail_stack)["StackResources"]
    assert fail_resources == [], (
        f"a stack that rolled back resolving Fn::If's selected branch must list no resources, "
        f"got {fail_resources!r}"
    )


def _poll_stack(cfn, stack_name: str, timeout_s: float = 240.0, interval_s: float = 4.0) -> str:
    """Poll DescribeStacks to a create-terminal state; return the final StackStatus. Raises on timeout."""
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
