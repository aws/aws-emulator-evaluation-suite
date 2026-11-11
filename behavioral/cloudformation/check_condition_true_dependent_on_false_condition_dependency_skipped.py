"""condition-true-dependent-on-false-condition-dependency-skipped."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "condition-true-dependent-on-false-condition-dependency-skipped"
GROUP = 'conditions'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED",
}


_UNRESOLVED_DEPENDENCY = (
    "ValidationError",
    "Template format error: Unresolved resource dependencies [Dependency] in the Resources block of the template",
)


def _describe(cf, name):
    """DescribeStacks for one stack, or None when AWS reports it does not exist."""
    try:
        return cf.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError as exc:
        err = exc.response["Error"]
        if (err.get("Code"), err.get("Message")) == ("ValidationError", f"Stack with id {name} does not exist"):
            return None
        raise


def _wait_terminal(cf, name, *, timeout_s=600, interval_s=5):
    """Poll DescribeStacks until the stack reaches a terminal state; return the stack."""
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        stack = _describe(cf, name)
        last = None if stack is None else stack["StackStatus"]
        if stack is not None and last in _TERMINAL_STATES:
            return stack
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"stack {name} did not reach a terminal state within {timeout_s}s (last={last!r})"
            )
        time.sleep(interval_s)


def expect_error(fn, code, message):
    """Assert ``fn()`` raises exactly ``(code, message)``."""
    try:
        result = fn()
    except ClientError as exc:
        got = (exc.response["Error"].get("Code"), exc.response["Error"].get("Message"))
        assert got == (code, message), f"expected {(code, message)!r}, got {got!r}"
        return
    raise AssertionError(f"expected {code} but the call succeeded: {result!r}")


def _delete_stack(cf, name, *, timeout_s=600, interval_s=5):
    """Delete a stack and wait until DescribeStacks no longer finds it; raise on DELETE_FAILED."""
    cf.delete_stack(StackName=name)
    deadline = time.monotonic() + timeout_s
    while True:
        stack = _describe(cf, name)
        if stack is None or stack["StackStatus"] == "DELETE_COMPLETE":
            return
        assert stack["StackStatus"] != "DELETE_FAILED", (
            f"stack {name} failed to delete: {stack.get('StackStatusReason')!r}"
        )
        if time.monotonic() >= deadline:
            raise AssertionError(f"stack {name} was not deleted within {timeout_s}s")
        time.sleep(interval_s)


def _delete_if_present(cf, name):
    """Delete a stack that a refused create should never have made; a no-op when it does not exist."""
    if _describe(cf, name) is not None:
        _delete_stack(cf, name)


def _template(dependent_condition):
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "CreateDependency": {"Type": "String", "AllowedValues": ["true", "false"]},
        },
        "Conditions": {
            # The dependent's own condition never depends on the parameter: it is true
            # no matter what the stack's input is.
            "AlwaysTrue": {"Fn::Equals": ["ready", "ready"]},
            "CreateDep": {"Fn::Equals": [{"Ref": "CreateDependency"}, "true"]},
        },
        "Resources": {
            "Always": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
            "Dependency": {"Type": "AWS::CloudFormation::WaitConditionHandle",
                            "Condition": "CreateDep"},
            "Dependent": {"Type": "AWS::CloudFormation::WaitConditionHandle",
                          "Condition": dependent_condition, "DependsOn": "Dependency"},
        },
    })


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A resource whose own Condition is always true cannot DependsOn a resource whose
    Condition can independently be false: CreateStack rejects the template up front."""
    cf = ctx.client("cloudformation")

    rejected = ctx.unique_name("sim2real-behav-conddep-bad-")
    ctx.on_cleanup(lambda: _delete_if_present(cf, rejected))
    expect_error(lambda: cf.create_stack(
        StackName=rejected, TemplateBody=_template("AlwaysTrue"),
        Parameters=[{"ParameterKey": "CreateDependency", "ParameterValue": "false"}],
    ), *_UNRESOLVED_DEPENDENCY)
    assert _describe(cf, rejected) is None, f"the rejected create must leave no stack behind: {rejected}"

    # positive control: giving the dependent the SAME condition as its DependsOn target
    # (so CloudFormation can prove the dependent is never created without it) is accepted,
    # and the pair is skipped together when that shared condition is false.
    accepted = ctx.unique_name("sim2real-behav-conddep-ok-")
    cf.create_stack(
        StackName=accepted, TemplateBody=_template("CreateDep"),
        Parameters=[{"ParameterKey": "CreateDependency", "ParameterValue": "false"}],
    )
    ctx.on_cleanup(lambda: _delete_stack(cf, accepted))
    obj = _wait_terminal(cf, accepted)
    assert obj["StackStatus"] == "CREATE_COMPLETE", (
        f"the same-condition template must create, got {obj['StackStatus']!r}: "
        f"{obj.get('StackStatusReason')!r}"
    )
    ids = {
        r["LogicalResourceId"]
        for r in cf.list_stack_resources(StackName=accepted)["StackResourceSummaries"]
    }
    assert ids == {"Always"}, (
        f"with a shared false condition, both the dependency and its dependent must be "
        f"skipped, got {sorted(ids)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
