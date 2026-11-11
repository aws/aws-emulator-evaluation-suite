"""deploy-iotcoredeviceadvisor-suitedefinition-empty-root-group-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-iotcoredeviceadvisor-suitedefinition-empty-root-group-rejected"
GROUP = "deploy"
SERVICES = ["cloudformation", "iam", "iotdeviceadvisor"]

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


def validation_rows(cf, stack_id):
    """Sorted ``(logical id, ValidationName, Status, FailureMode, Reason, Path)`` rows."""
    return sorted(
        (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
         e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
        for e in paginate(cf, "describe_events", "OperationEvents", StackName=stack_id)
        if e.get("EventType") == "VALIDATION_ERROR"
    )


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

_EMPTY_ROOT_GROUP = (
    "Suite", "PROPERTY_VALIDATION", "FAILED", "FAIL",
    "#/SuiteDefinitionConfiguration/RootGroup: expected minLength: 1, actual: 0",
    "/Resources/Suite/Properties/SuiteDefinitionConfiguration/RootGroup",
)
_STACK_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of "
    "issues with resource and property details, resolve each error, then retry the operation."
)


def _root_group() -> str:
    return json.dumps({
        "configuration": {},
        "tests": [{
            "name": "sim2real-group",
            "configuration": {},
            "tests": [{
                "name": "sim2real-test",
                "configuration": {},
                "test": {"id": "MQTT_Connect", "version": "0.0.0"},
            }],
        }],
    })


def _template(suite_name: str, role_arn: str, root_group: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Suite": {
                "Type": "AWS::IoTCoreDeviceAdvisor::SuiteDefinition",
                "Properties": {
                    "SuiteDefinitionConfiguration": {
                        "SuiteDefinitionName": suite_name,
                        "DevicePermissionRoleArn": role_arn,
                        "RootGroup": root_group,
                    },
                },
            },
        },
        "Outputs": {"SuiteId": {"Value": {"Ref": "Suite"}}},
    })


def _suite_ids_named(iotda, name: str) -> list[str]:
    ids: list[str] = []
    kwargs: dict = {}
    while True:
        page = iotda.list_suite_definitions(**kwargs)
        ids.extend(s["suiteDefinitionId"] for s in page["suiteDefinitionInformationList"]
                   if s["suiteDefinitionName"] == name)
        if not page.get("nextToken"):
            return ids
        kwargs["nextToken"] = page["nextToken"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An AWS::IoTCoreDeviceAdvisor::SuiteDefinition with an empty RootGroup fails property
    validation before any resource is touched and Device Advisor never gains the suite; the same
    template with a valid RootGroup deploys and reads back at Device Advisor.

    Reference: https://docs.aws.amazon.com/AWSCloudFormation/latest/TemplateReference/aws-resource-iotcoredeviceadvisor-suitedefinition.html
    """
    cfn = ctx.client("cloudformation")
    iam = ctx.client("iam")
    iotda = ctx.client("iotdeviceadvisor")
    stack_name = ctx.unique_name("sim2real-behav-devadv-bad-")
    good_stack_name = ctx.unique_name("sim2real-behav-devadv-good-")
    suite_name = ctx.unique_name("sim2real-behav-devadv-bad-suite-")
    role_name = ctx.unique_name("sim2real-behav-devadv-bad-role-")

    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "iotdeviceadvisor.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": role_name}],
    )["Role"]["Arn"]

    stack_id = create_stack(ctx, cfn, stack_name, _template(suite_name, role_arn, ""))
    status = wait_stack(cfn, stack_id)
    assert status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {status!r}"

    stack_failed = [e.get("ResourceStatusReason") for e in stack_events(cfn, stack_id)
                    if e["LogicalResourceId"] == stack_name and e["ResourceStatus"] == "CREATE_FAILED"]
    assert stack_failed == [_STACK_REASON], (
        f"the stack's CREATE_FAILED reasons were {stack_failed!r}, expected [{_STACK_REASON!r}]"
    )
    found = validation_rows(cfn, stack_id)
    assert found == [_EMPTY_ROOT_GROUP], (
        f"validation errors of the create: expected {[_EMPTY_ROOT_GROUP]!r}, got {found!r}"
    )

    # Rejected before provisioning: no resource record, and Device Advisor never saw the suite.
    resources = cfn.describe_stack_resources(StackName=stack_id)["StackResources"]
    assert resources == [], f"a stack rejected before provisioning reports resources {resources!r}"
    absent = _suite_ids_named(iotda, suite_name)
    assert absent == [], f"expected no Device Advisor suite named {suite_name!r}, found {absent!r}"
    delete_stack(cfn, stack_id)

    # Positive control: the same template, the same suite name, a valid RootGroup.
    good_id = create_stack(ctx, cfn, good_stack_name,
                           _template(suite_name, role_arn, _root_group()))
    good_status = wait_stack(cfn, good_id)
    assert good_status == "CREATE_COMPLETE", (
        f"the control stack with a valid RootGroup ended {good_status!r}, expected CREATE_COMPLETE: "
        f"{decisive_rows(stack_events(cfn, good_id))!r}"
    )
    suite_id = stack_outputs(cfn, good_id)["SuiteId"]
    listed = _suite_ids_named(iotda, suite_name)
    assert listed == [suite_id], (
        f"Ref of the control suite is {suite_id!r}, Device Advisor lists {suite_name!r} under {listed!r}"
    )
    config = iotda.get_suite_definition(suiteDefinitionId=suite_id)["suiteDefinitionConfiguration"]
    root = json.loads(config["rootGroup"])
    got = (config["suiteDefinitionName"], config["devicePermissionRoleArn"],
           [g["name"] for g in root["tests"]], [t["name"] for t in root["tests"][0]["tests"]])
    want_control = (suite_name, role_arn, ["sim2real-group"], ["sim2real-test"])
    assert got == want_control, (
        f"expected the control suite (name, role, groups, tests) {want_control!r}, Device Advisor "
        f"reports {got!r}"
    )

    delete_stack(cfn, good_id)
    suite_gone = (
        "ResourceNotFoundException", f"Unable to find resource with suiteDefinitionId: {suite_id}"
    )
    expect_error(lambda: iotda.get_suite_definition(suiteDefinitionId=suite_id), *suite_gone)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
