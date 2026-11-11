"""create-stack-exceeding-parameter-count-limit-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-stack-exceeding-parameter-count-limit-rejected"
GROUP = "negative-classes"
SERVICES = ["cloudformation"]


def _template_with_params(count: int) -> str:
    params = {f"Param{i}": {"Type": "String", "Default": "x"} for i in range(count)}
    return json.dumps({"Parameters": params, "Resources": {"Topic": {"Type": "AWS::SNS::Topic"}}})


@tags("axis:rejection", "cap:c3", "concern:deploy", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack with a template declaring more than the 200-parameter-per-template limit is
    rejected as a template-content error (distinct from the account/region resource-count
    LimitExceededException), and a template safely under the limit still creates."""
    cfn = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-cfn-params-")

    over_limit_template = _template_with_params(201)
    code, message = _error(
        lambda: cfn.create_stack(StackName=name, TemplateBody=over_limit_template),
        "CreateStack with 201 parameters",
    )
    assert code == "ValidationError", f"expected ValidationError, got {code}"
    expected = "Template format error: Parameter count 201 is greater than max allowed 200"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # (b) effect absent: no stack was created for this name
    not_found_code, not_found_message = _error(
        lambda: cfn.describe_stacks(StackName=name),
        "DescribeStacks for a stack that was never created",
    )
    assert not_found_code == "ValidationError", f"expected stack-not-found ValidationError, got {not_found_code}"
    assert not_found_message == f"Stack with id {name} does not exist", (
        f"expected the exact stack-not-found message, got {not_found_message!r}"
    )

    # (c) positive control: a template comfortably under the limit still creates
    under_limit_template = _template_with_params(5)
    cfn.create_stack(StackName=name, TemplateBody=under_limit_template)
    ctx.on_cleanup(lambda: _safe_delete_stack(ctx, name))
    _wait_stack_status(ctx, name, {"CREATE_COMPLETE"})


def _error(fn, description):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected {description} to fail, but it SUCCEEDED and returned {result!r}")


def _safe_delete_stack(ctx, name):
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise


def _wait_stack_status(ctx, name, terminal_statuses, timeout_s=180.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        stacks = cfn.describe_stacks(StackName=name)["Stacks"]
        last = stacks[0]["StackStatus"]
        if last in terminal_statuses:
            return last
        if last.endswith("FAILED") or "ROLLBACK" in last:
            raise AssertionError(f"stack {name} entered unexpected status {last}")
        time.sleep(interval_s)
    raise AssertionError(f"stack {name} never reached {terminal_statuses}, last={last}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
