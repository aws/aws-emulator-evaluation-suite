"""parameter-type-mismatch-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "parameter-type-mismatch-rejected"
GROUP = "representation"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateStack with a non-numeric value for a Number parameter fails with ValidationError "Parameter
    'Count' must be a number." and creates no stack; the value "42" deploys and is echoed back, and after
    that stack is deleted DescribeStacks and UpdateStack report it does not exist."""
    cfn = ctx.client("cloudformation")
    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {"Count": {"Type": "Number"}},
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    }
    template_body = json.dumps(template)

    # --- broken: non-numeric value for a Number parameter ---
    bad_stack_name = ctx.unique_name("sim2real-behav-badnum-")
    code, message = _error(
        lambda: cfn.create_stack(
            StackName=bad_stack_name,
            TemplateBody=template_body,
            Parameters=[{"ParameterKey": "Count", "ParameterValue": "not-a-number"}],
        )
    )
    assert code == "ValidationError", f"expected ValidationError, got {code!r}"
    expected = "Parameter 'Count' must be a number."
    assert message == expected, f"expected type-mismatch message {expected!r}, got {message!r}"

    # Effect must be absent: the stack must never have been created.
    describe_code, describe_message = _error(lambda: cfn.describe_stacks(StackName=bad_stack_name))
    assert describe_code == "ValidationError", (
        f"expected DescribeStacks to report the bad stack does not exist, got {describe_code!r}"
    )
    expected = f"Stack with id {bad_stack_name} does not exist"
    assert describe_message == expected, f"expected message {expected!r}, got {describe_message!r}"

    # --- positive control: identical template, valid numeric value succeeds ---
    good_stack_name = ctx.unique_name("sim2real-behav-goodnum-")
    cfn.create_stack(
        StackName=good_stack_name,
        TemplateBody=template_body,
        Parameters=[{"ParameterKey": "Count", "ParameterValue": "42"}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=good_stack_name))
    _wait_for_stack_status(ctx, good_stack_name, {"CREATE_COMPLETE"}, timeout_s=120)

    stack = cfn.describe_stacks(StackName=good_stack_name)["Stacks"][0]
    params = {p["ParameterKey"]: p["ParameterValue"] for p in stack["Parameters"]}
    assert params["Count"] == "42", (
        f"expected the Number parameter to be echoed back as the string '42', got {params.get('Count')!r}"
    )

    # Once deletion finishes, DescribeStacks by name reports the same "does not exist"
    # ValidationError as for a stack never created, and UpdateStack cannot resurrect it.
    cfn.delete_stack(StackName=good_stack_name)
    _wait_for_stack_deleted(ctx, good_stack_name, timeout_s=120)
    deleted_code, deleted_message = _error(lambda: cfn.describe_stacks(StackName=good_stack_name))
    assert deleted_code == "ValidationError", (
        f"expected DescribeStacks to report the deleted stack does not exist, got {deleted_code!r}"
    )
    expected = f"Stack with id {good_stack_name} does not exist"
    assert deleted_message == expected, f"expected message {expected!r}, got {deleted_message!r}"

    update_code, update_message = _error(
        lambda: cfn.update_stack(
            StackName=good_stack_name,
            TemplateBody=template_body,
            Parameters=[{"ParameterKey": "Count", "ParameterValue": "43"}],
        )
    )
    assert update_code == "ValidationError", (
        f"expected UpdateStack on the deleted stack to be rejected, got {update_code!r}"
    )
    expected = f"Stack [{good_stack_name}] does not exist"
    assert update_message == expected, f"expected message {expected!r}, got {update_message!r}"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises. An unexpected
    success raises, so a target that accepts a call AWS refuses fails as an acceptance rather
    than as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is not None:
            err = response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_stack_status(ctx, stack_name, terminal_statuses, timeout_s=120.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        last = resp["Stacks"][0]["StackStatus"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} never reached {terminal_statuses}, last status {last}")


def _wait_for_stack_deleted(ctx, stack_name, timeout_s=120.0, interval_s=3.0):
    """Poll until DescribeStacks reports the stack gone (ValidationError) or raise."""
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except Exception as exc:  # noqa: BLE001
            response = getattr(exc, "response", None)
            code = response.get("Error", {}).get("Code") if response is not None else None
            if code == "ValidationError":
                return
            raise
        last = resp["Stacks"][0]["StackStatus"]
        if last == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} failed to delete: DELETE_FAILED")
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name} was not deleted within {timeout_s}s, last status {last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
