"""invalid-template-error."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-template-error"
GROUP = 'errors'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED",
}


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected success raises, so a target that
    accepts a request AWS refuses fails as an acceptance rather than as an error-code
    mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _wait_terminal(cf, name, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError:
            last = "UNKNOWN"
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} terminal not met within {timeout_s}s (last={last!r})")


def _valid_template():
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {"Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"}},
    })


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack with a malformed template body fails with ValidationError "Template format
    error: unsupported structure." and DescribeStacks then reports the name does not exist; a
    valid template reaches CREATE_COMPLETE."""
    cf = ctx.client("cloudformation")

    # Positive control: a minimal, valid template must succeed and reach CREATE_COMPLETE.
    good_name = ctx.unique_name("sim2real-behav-stk-good-")
    cf.create_stack(StackName=good_name, TemplateBody=_valid_template())
    ctx.on_cleanup(lambda: cf.delete_stack(StackName=good_name))
    good_status = _wait_terminal(cf, good_name)
    assert good_status == "CREATE_COMPLETE", (
        f"positive control did not reach CREATE_COMPLETE: {good_status!r}"
    )

    # Negative: a malformed template body must be rejected with the specific error code.
    bad_name = ctx.unique_name("sim2real-behav-stk-bad-")
    error = _client_error(lambda: cf.create_stack(
        StackName=bad_name,
        TemplateBody="this is not valid json or yaml {",
    ))
    assert error.get("Code") == "ValidationError", (
        f"Expected ValidationError, got {error.get('Code')!r}"
    )
    assert error.get("Message") == "Template format error: unsupported structure.", (
        f"expected message 'Template format error: unsupported structure.', got {error!r}"
    )

    # Effect-absent: the rejection must be up front -- no stack exists under that name at all.
    describe_error = _client_error(lambda: cf.describe_stacks(StackName=bad_name))
    assert describe_error.get("Code") == "ValidationError", (
        f"expected no stack to exist after the rejected CreateStack, but describe_stacks gave "
        f"{describe_error!r}"
    )
    expected_describe_message = f"Stack with id {bad_name} does not exist"
    assert describe_error.get("Message") == expected_describe_message, (
        f"expected message {expected_describe_message!r}, got {describe_error!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
