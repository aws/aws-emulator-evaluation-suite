"""circular-dependency-rejected-state-unchanged."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "circular-dependency-rejected-state-unchanged"
GROUP = 'errors'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}


def _describe(cf, name):
    """DescribeStacks for one stack, or None when it no longer exists."""
    try:
        return cf.describe_stacks(StackName=name)["Stacks"][0]
    except ClientError:
        return None


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


def _error(fn):
    """Call fn(); return (code, message) of the ClientError raised; raise if it succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")




def _acyclic(name_a, name_b):
    """B depends on A. A legal, resolvable dependency chain."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ParamA": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": name_a, "Type": "String", "Value": "a-value"},
            },
            "ParamB": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": name_b, "Type": "String",
                               "Value": {"Fn::Sub": "b-of-${ParamA}"}},
            },
        },
    })


def _cyclic(name_a, name_b):
    """A depends on B and B depends on A -- structurally unschedulable."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ParamA": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": name_a, "Type": "String",
                               "Value": {"Fn::Sub": "a-of-${ParamB}"}},
            },
            "ParamB": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": name_b, "Type": "String",
                               "Value": {"Fn::Sub": "b-of-${ParamA}"}},
            },
        },
    })


def _dangling_ref(name_a, name_b):
    """ParamB refers to a logical id that does not exist in the template."""
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ParamA": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": name_a, "Type": "String", "Value": "a-value"},
            },
            "ParamB": {
                "Type": "AWS::SSM::Parameter",
                "Properties": {"Name": name_b, "Type": "String",
                               "Value": {"Fn::Sub": "b-of-${DoesNotExist}"}},
            },
        },
    })


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An update with a Ref cycle or a dangling Ref is rejected with ValidationError and leaves
    the stack unchanged (status, resources, values); a valid update afterwards still succeeds."""
    cf = ctx.client("cloudformation")
    ssm = ctx.client("ssm")

    stack = ctx.unique_name("sim2real-behav-cycle-")
    name_a = "/" + ctx.unique_name("sim2real-behav-cycle-a-")
    name_b = "/" + ctx.unique_name("sim2real-behav-cycle-b-")

    # Full valid setup: the acyclic version of exactly the same template.
    cf.create_stack(
        StackName=stack,
        TemplateBody=_acyclic(name_a, name_b),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=stack))
    created = _wait_terminal(cf, stack)
    assert created["StackStatus"] == "CREATE_COMPLETE", (
        f"the acyclic control template must create, got {created['StackStatus']!r}: "
        f"{created.get('StackStatusReason')!r}"
    )
    baseline_b = ssm.get_parameter(Name=name_b)["Parameter"]["Value"]
    assert baseline_b == f"b-of-{name_a}", (
        f"Fn::Sub over a resource Ref must resolve to the referenced physical id, got {baseline_b!r}"
    )
    baseline_ids = sorted(
        r["LogicalResourceId"]
        for r in cf.list_stack_resources(StackName=stack)["StackResourceSummaries"]
    )

    # Break exactly one thing: make the dependency mutual.
    code, message = _error(
        lambda: cf.update_stack(StackName=stack, TemplateBody=_cyclic(name_a, name_b))
    )
    assert code == "ValidationError", (
        f"a circular resource dependency must be rejected with ValidationError, got {code!r}"
    )
    expected = "Circular dependency between resources: [ParamB, ParamA]"
    assert message == expected, (
        f"the rejection must identify the cycle, expected {expected!r}, got {message!r}"
    )

    # Effect absent: no update was ever started.
    still = _describe(cf, stack)
    assert still is not None and still["StackStatus"] == "CREATE_COMPLETE", (
        f"a synchronously rejected update must not move the stack off CREATE_COMPLETE, got "
        f"{None if still is None else still['StackStatus']!r}"
    )
    after_cycle_ids = sorted(
        r["LogicalResourceId"]
        for r in cf.list_stack_resources(StackName=stack)["StackResourceSummaries"]
    )
    assert after_cycle_ids == baseline_ids, (
        f"a rejected circular update must not change the resource set, "
        f"expected {baseline_ids!r}, got {after_cycle_ids!r}"
    )
    assert ssm.get_parameter(Name=name_b)["Parameter"]["Value"] == baseline_b, (
        "the rejected update must not have touched the provisioned resources"
    )

    # A second, distinct semantic failure on the same live stack: a dangling Ref.
    code2, message2 = _error(
        lambda: cf.update_stack(StackName=stack, TemplateBody=_dangling_ref(name_a, name_b))
    )
    assert code2 == "ValidationError", (
        f"a Ref to a non-existent logical id must be rejected with ValidationError, got {code2!r}"
    )
    expected2 = (
        "Template format error: Unresolved resource dependencies [DoesNotExist] "
        "in the Resources block of the template"
    )
    assert message2 == expected2, (
        f"the rejection must name the unresolved reference, expected {expected2!r}, got {message2!r}"
    )
    still2 = _describe(cf, stack)
    assert still2 is not None and still2["StackStatus"] == "CREATE_COMPLETE", (
        f"a synchronously rejected dangling-ref update must not move the stack off "
        f"CREATE_COMPLETE, got {None if still2 is None else still2['StackStatus']!r}"
    )
    after_dangling_b = ssm.get_parameter(Name=name_b)["Parameter"]["Value"]
    assert after_dangling_b == baseline_b, (
        f"the rejected dangling-ref update must not have touched the provisioned resources, "
        f"expected {baseline_b!r}, got {after_dangling_b!r}"
    )

    # Control: the stack still accepts a legitimate update.
    cf.update_stack(
        StackName=stack,
        TemplateBody=_acyclic(name_a, name_b).replace('"a-value"', '"a-value-2"'),
    )
    updated = _wait_terminal(cf, stack)
    assert updated["StackStatus"] == "UPDATE_COMPLETE", (
        f"the stack must not be wedged by the rejections, got {updated['StackStatus']!r}: "
        f"{updated.get('StackStatusReason')!r}"
    )
    final_a = ssm.get_parameter(Name=name_a)["Parameter"]["Value"]
    assert final_a == "a-value-2", (
        f"the restored valid update must actually provision its new value, "
        f"expected 'a-value-2', got {final_a!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
