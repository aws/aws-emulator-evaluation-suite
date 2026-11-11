"""create-failure-rollback."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-failure-rollback"
GROUP = 'rollback'
SERVICES = ['cloudformation']
#: The default service-class budget; the harness deadline bounds the run.
POLL_BUDGET_S = 300.0


def _dangling_dependson_template() -> str:
    """DependsOn names a logical id that is not present anywhere in Resources."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Bad": {
                    "Type": "AWS::CloudFormation::WaitConditionHandle",
                    "DependsOn": "DoesNotExist",
                }
            },
        }
    )


def _resolved_dependson_template(queue_name: str) -> str:
    """The same resource graph with the DependsOn target present and resolvable; the dependent is
    a real SQS queue so CREATE_COMPLETE is backed by a provisioned resource."""
    return json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "Handle": {"Type": "AWS::CloudFormation::WaitConditionHandle"},
                "Good": {
                    "Type": "AWS::SQS::Queue",
                    "DependsOn": "Handle",
                    "Properties": {
                        "QueueName": queue_name,
                        "Tags": [{"Key": "sim2real-behav", "Value": queue_name}],
                    },
                },
            },
        }
    )


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateStack of a template whose DependsOn names an absent logical id is refused synchronously
    with ValidationError and the exact unresolved-dependency message and no stack appears, while
    the same graph with the dependency present reaches CREATE_COMPLETE with its queue at SQS."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-stk-")
    # Registered first: a target that accepts the invalid template must not leak its stack.
    ctx.on_cleanup(lambda: _delete_stack(cf, name))

    refused = _expect_error(
        lambda: cf.create_stack(StackName=name, TemplateBody=_dangling_dependson_template()),
        ("ValidationError",),
    )
    expected_message = (
        "Template format error: Unresolved resource dependencies [DoesNotExist] in the Resources block"
        " of the template"
    )
    assert refused.response["Error"]["Message"] == expected_message, (
        f"expected the message {expected_message!r}, got {refused.response['Error']['Message']!r}"
    )

    # Effect absent: no stack was ever created for this name -- an independent read,
    # through DescribeStacks rather than the CreateStack call that was rejected.
    refused = _expect_error(lambda: cf.describe_stacks(StackName=name), ("ValidationError",))
    expected_message = f"Stack with id {name} does not exist"
    assert refused.response["Error"]["Message"] == expected_message, (
        f"expected the message {expected_message!r}, got {refused.response['Error']['Message']!r}"
    )

    # Positive control: the same resource graph with the dependency resolved creates cleanly,
    # proving the rejection above is specific to the dangling reference, not to this template
    # shape or account in general.
    queue_name = ctx.unique_name("sim2real-behav-q-")
    cf.create_stack(StackName=name, TemplateBody=_resolved_dependson_template(queue_name))
    status = _wait_terminal(cf, name)
    assert status == "CREATE_COMPLETE", f"positive control expected CREATE_COMPLETE, got {status}"
    # No fake success: the queue the stack reports is really there at SQS.
    queue_url = ctx.client("sqs").get_queue_url(QueueName=queue_name)["QueueUrl"]
    assert queue_url.rstrip("/").endswith(f"/{queue_name}"), f"unexpected queue URL {queue_url!r}"


_TERMINAL_STATES = {
    "CREATE_COMPLETE", "CREATE_FAILED", "DELETE_COMPLETE", "DELETE_FAILED",
    "ROLLBACK_COMPLETE", "ROLLBACK_FAILED", "UPDATE_COMPLETE", "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE", "UPDATE_ROLLBACK_FAILED", "IMPORT_COMPLETE",
    "IMPORT_ROLLBACK_COMPLETE", "IMPORT_ROLLBACK_FAILED",
}


def _assert_error(exc, codes, *, status=400, contains=()) -> None:
    """Grade a ClientError on code, HTTP status, the exact message and the ids it must name."""
    err = exc.response.get('Error', {})
    code, msg = err.get('Code'), err.get('Message') or ''
    got_status = exc.response.get('ResponseMetadata', {}).get('HTTPStatusCode')
    assert code in codes, f"expected error code in {codes!r}, got {code!r}: {msg!r}"
    assert got_status == status, f"expected HTTP {status} with {code}, got {got_status!r}"
    assert msg.strip(), f"expected the exact message with {code}"
    for want in contains:
        assert want in msg, f"expected the {code} message to name {want!r}, got {msg!r}"


def _expect_error(fn, codes, *, status=400, contains=()):
    """Call fn() and grade the ClientError it raises; an accepted call is itself a failure."""
    try:
        result = fn()
    except ClientError as exc:
        _assert_error(exc, codes, status=status, contains=contains)
        return exc
    raise AssertionError(f'expected {codes!r}, but the call succeeded: {result!r}')


def _wait_terminal(cf, name, timeout_s=POLL_BUDGET_S):
    """Poll DescribeStacks until the stack reaches a terminal state; return it."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = cf.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"]
        except Exception:
            last = "UNKNOWN"
        if last in _TERMINAL_STATES:
            return last
        time.sleep(2)
    raise AssertionError(f"stack {name} terminal not met within {timeout_s}s (last={last!r})")


def _delete_stack(cf, name):
    """Teardown: delete the stack and wait for DELETE_COMPLETE; a failed delete raises."""
    cf.delete_stack(StackName=name)
    cf.get_waiter("stack_delete_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
