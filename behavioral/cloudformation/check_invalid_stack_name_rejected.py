"""invalid-stack-name-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "invalid-stack-name-rejected"
GROUP = 'overly-permissive'
SERVICES = ['cloudformation']

_TERMINAL_STATES = {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack with a name violating [a-zA-Z][-a-zA-Z0-9]* fails with ValidationError and the exact
    pattern message, DescribeStacks on that name fails the same way, and the same template under a valid
    name reaches CREATE_COMPLETE."""
    cfn = ctx.client("cloudformation")
    tmpl = _sns_topic_template(ctx.unique_name("sim2real-behav-cfn-topic-"))
    good_name = ctx.unique_name("sim2real-behav-cfn-good-")
    bad_name = ctx.unique_name("sim2real-behav-cfn-bad-") + "_invalid.name"

    # Positive control: the identical call shape, a valid name.
    cfn.create_stack(
        StackName=good_name, TemplateBody=tmpl,
        Tags=[{"Key": "sim2real", "Value": "invalid-stack-name-rejected"}],
    )
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=good_name))
    status = _wait_terminal(cfn, good_name)
    assert status == "CREATE_COMPLETE", (
        f"the positive control (valid stack name, same template) did not reach "
        f"CREATE_COMPLETE: {status!r}"
    )

    error = _client_error(lambda: cfn.create_stack(StackName=bad_name, TemplateBody=tmpl))
    assert error.get("Code") == "ValidationError", (
        f"a stack name violating [a-zA-Z][-a-zA-Z0-9]* was not rejected with "
        f"ValidationError, got {error!r}"
    )
    expected_message = (
        f"1 validation error detected: Value '{bad_name}' at 'stackName' failed to satisfy "
        f"constraint: Member must satisfy regular expression pattern: [a-zA-Z][-a-zA-Z0-9]*"
    )
    assert error.get("Message") == expected_message, f"expected message {expected_message!r}, got {error!r}"

    # Independent read at the destination: no stack exists under the rejected name.
    describe_error = _client_error(lambda: cfn.describe_stacks(StackName=bad_name))
    assert describe_error.get("Code") == "ValidationError", (
        f"expected no stack to exist after the rejected CreateStack, but describe_stacks "
        f"gave {describe_error!r}"
    )
    expected_describe_message = (
        f"1 validation error detected: Value '{bad_name}' at 'stackName' failed to satisfy "
        f"constraint: Member must satisfy regular expression pattern: "
        f"[a-zA-Z][-a-zA-Z0-9]*|arn:[-a-zA-Z0-9:/._+]*"
    )
    assert describe_error.get("Message") == expected_describe_message, (
        f"expected message {expected_describe_message!r}, got {describe_error!r}"
    )


def _wait_terminal(cfn, name, timeout_s=180):
    deadline = time.monotonic() + timeout_s
    last = "UNKNOWN"
    while time.monotonic() < deadline:
        try:
            last = cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except ClientError:
            last = "UNKNOWN"
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(
        f"stack {name!r} did not reach a terminal state within {timeout_s}s (last={last!r})"
    )


def _client_error(fn):
    """Call fn(); return the botocore Error dict if a ClientError is raised. An unexpected
    success raises, so a target that accepts input AWS refuses fails as an acceptance rather
    than as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _sns_topic_template(topic_name, display_name=None) -> str:
    props = {"TopicName": topic_name}
    if display_name is not None:
        props["DisplayName"] = display_name
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {"MyTopic": {"Type": "AWS::SNS::Topic", "Properties": props}},
            "Outputs": {"TopicArnOutput": {"Value": {"Ref": "MyTopic"}}},
        }
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
