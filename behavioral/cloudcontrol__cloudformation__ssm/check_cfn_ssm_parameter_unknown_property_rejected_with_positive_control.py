"""cfn-ssm-parameter-unknown-property-rejected-with-positive-control."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ssm-parameter-unknown-property-rejected-with-positive-control"
GROUP = "deploy"
SERVICES = ["cloudcontrol", "cloudformation", "ssm"]

_CREATE_TERMINAL = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}
_DELETE_TERMINAL = {"DELETE_COMPLETE", "DELETE_FAILED"}
_SCHEMA_FAILURE_REASON = (
    "Validation failed with 1 error(s). Call DescribeEvents to retrieve the full list of issues "
    "with resource and property details, resolve each error, then retry the operation."
)
_VALIDATION_ROWS = [(
    "Param", "PROPERTY_VALIDATION", "FAILED", "FAIL",
    "Unsupported property [ThisPropertyDoesNotExist]",
    "/Resources/Param/Properties/ThisPropertyDoesNotExist",
)]
_VALUE = "sim2real-behav-value"


def _poll(cf, stack_id: str, terminal: set, *, timeout_s: float = 240.0) -> str:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cf.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {stack_id!r} not terminal within {timeout_s}s (last={last!r})")


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _failure_reason(cf, stack_id: str, logical_id: str) -> str:
    """Reason of the stack's own CREATE_FAILED row (LogicalResourceId is the stack name)."""
    for page in cf.get_paginator("describe_stack_events").paginate(StackName=stack_id):
        for event in page["StackEvents"]:
            if (event["ResourceStatus"] == "CREATE_FAILED"
                    and event["LogicalResourceId"] == logical_id
                    and event.get("ResourceStatusReason")):
                return event["ResourceStatusReason"]
    raise AssertionError(f"no CREATE_FAILED event for {logical_id!r} carrying a reason in {stack_id!r}")


def _validation_errors(cf, stack_id: str) -> list[tuple]:
    """``(logical id, name, status, mode, reason, path)`` of every VALIDATION_ERROR event."""
    out: list[tuple] = []
    kwargs = {"StackName": stack_id}
    while True:
        page = cf.describe_events(**kwargs)
        out.extend(
            (e.get("LogicalResourceId"), e.get("ValidationName"), e.get("ValidationStatus"),
             e.get("ValidationFailureMode"), e.get("ValidationStatusReason"), e.get("ValidationPath"))
            for e in page["OperationEvents"] if e.get("EventType") == "VALIDATION_ERROR"
        )
        if not page.get("NextToken"):
            return out
        kwargs["NextToken"] = page["NextToken"]


def _template(name: str, *, unknown: bool) -> str:
    props = {"Name": name, "Type": "String", "Value": _VALUE}
    if unknown:
        props["ThisPropertyDoesNotExist"] = 1
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Param": {"Type": "AWS::SSM::Parameter", "Properties": props}},
    })


@tags("axis:rejection", "cap:c1", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An unknown property on a CFN AWS::SSM::Parameter fails early validation at its own path and
    creates no parameter, while the same template without it deploys with its Type and Value.
    """
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")
    cc = ctx.client("cloudcontrol")

    bad_name = ctx.unique_name("sim2real-behav-ssmneg-")
    bad_stack = ctx.unique_name("sim2real-behav-ssmnegstack-")
    bad_stack_id = cf.create_stack(
        StackName=bad_stack, TemplateBody=_template(bad_name, unknown=True),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, bad_stack_id))

    bad_status = _poll(cf, bad_stack_id, _CREATE_TERMINAL)
    assert bad_status == "ROLLBACK_COMPLETE", f"expected ROLLBACK_COMPLETE, got {bad_status!r}"
    reason = _failure_reason(cf, bad_stack_id, bad_stack)
    assert reason == _SCHEMA_FAILURE_REASON, (
        f"expected the resource-schema failure reason {_SCHEMA_FAILURE_REASON!r}, got {reason!r}"
    )
    rows = _validation_errors(cf, bad_stack_id)
    assert rows == _VALIDATION_ROWS, f"VALIDATION_ERROR rows expected {_VALIDATION_ROWS!r}, got {rows!r}"

    got = _error(lambda: ssm.get_parameter(Name=bad_name))
    assert got == ("ParameterNotFound", ""), (
        f"the rolled-back stack must have created no parameter {bad_name!r}: expected "
        f"('ParameterNotFound', ''), got {got!r}"
    )

    # Positive control: the same template, minus the unknown property, reaches CREATE_COMPLETE.
    good_name = ctx.unique_name("sim2real-behav-ssmctl-")
    good_stack = ctx.unique_name("sim2real-behav-ssmctlstack-")
    good_stack_id = cf.create_stack(
        StackName=good_stack, TemplateBody=_template(good_name, unknown=False),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: _delete_stack(cf, good_stack_id))

    good_status = _poll(cf, good_stack_id, _CREATE_TERMINAL)
    assert good_status == "CREATE_COMPLETE", f"expected CREATE_COMPLETE, got {good_status!r}"

    live = ssm.get_parameter(Name=good_name)["Parameter"]
    got = (live["Name"], live["Type"], live["Value"])
    assert got == (good_name, "String", _VALUE), (
        f"GetParameter (Name, Type, Value) expected {(good_name, 'String', _VALUE)!r}, got {got!r}"
    )

    cc_props = json.loads(cc.get_resource(TypeName="AWS::SSM::Parameter", Identifier=good_name)[
        "ResourceDescription"]["Properties"])
    got_cc = (cc_props.get("Name"), cc_props.get("Type"), cc_props.get("Value"))
    assert got_cc == (good_name, "String", _VALUE), (
        f"Cloud Control's model (Name, Type, Value) expected {(good_name, 'String', _VALUE)!r}, "
        f"got {got_cc!r}"
    )


def _delete_stack(cf, stack_id: str) -> None:
    cf.delete_stack(StackName=stack_id)
    status = _poll(cf, stack_id, _DELETE_TERMINAL)
    if status != "DELETE_COMPLETE":
        raise AssertionError(f"stack {stack_id!r} ended {status!r}, expected DELETE_COMPLETE")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
