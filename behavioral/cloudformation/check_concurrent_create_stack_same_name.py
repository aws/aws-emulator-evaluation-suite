"""concurrent-create-stack-same-name."""
from __future__ import annotations

import concurrent.futures
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-stack-same-name"
GROUP = 'concurrency'
SERVICES = ['cloudformation']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Five racing CreateStack calls for one stack name yield exactly one success; the other four
    are refused with AlreadyExistsException and "Stack [<name>] already exists", and SNS holds
    only the winning template's topic."""
    cfn = ctx.client("cloudformation")
    sns = ctx.client("sns")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    name = ctx.unique_name("sim2real-behav-cfn-race-")
    n = 5
    topic_names = [ctx.unique_name(f"sim2real-behav-cfn-race-topic-{i}-") for i in range(n)]

    def attempt(i):
        tmpl = _sns_topic_template(topic_names[i])
        return cfn.create_stack(StackName=name, TemplateBody=tmpl)

    results = _run_concurrent([lambda i=i: attempt(i) for i in range(n)])
    ctx.on_cleanup(lambda: _delete_stack_quiet(cfn, name))
    final_status = _wait_stack_status(cfn, name).get("StackStatus")

    successes = _concurrent_successes(results)
    errors = _concurrent_error_codes(results)
    winners = [i for i, r in enumerate(results) if not isinstance(r, BaseException)]

    assert successes == 1, f"expected exactly one winning CreateStack, got {successes}"
    assert len(errors) == n - 1, f"expected {n - 1} losers, got {len(errors)}"
    assert all(code == "AlreadyExistsException" for code in errors), errors
    messages = [r.response.get("Error", {}).get("Message") for r in results if isinstance(r, ClientError)]
    assert all(message == f"Stack [{name}] already exists" for message in messages), messages
    assert final_status == "CREATE_COMPLETE", (
        f"winning CreateStack should have deployed cleanly, got {final_status}"
    )

    winner_topic = topic_names[winners[0]]
    provisioned = {
        i for i, topic_name in enumerate(topic_names)
        if _topic_exists(sns, account_id, ctx.region, topic_name)
    }
    assert provisioned == {winners[0]}, (
        f"expected only the winner's topic ({winner_topic!r}, index {winners[0]}) to be "
        f"provisioned at the SNS destination, found indices {sorted(provisioned)}"
    )


_TERMINAL_STACK_STATUSES = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "UPDATE_COMPLETE",
    "UPDATE_FAILED",
    "UPDATE_ROLLBACK_COMPLETE",
    "UPDATE_ROLLBACK_FAILED",
    "DELETE_COMPLETE",
    "DELETE_FAILED",
}


def _run_concurrent(fns, *, timeout_s=60.0):
    """Run callables in parallel; return results in submission order.

    Each entry is either the callable's return value or the Exception it raised (captured,
    NOT re-raised) so the check can assert on the DISTRIBUTION of outcomes.
    """
    results = [None] * len(fns)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns))) as ex:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
            idx = future_to_idx[fut]
            try:
                results[idx] = fut.result()
            except Exception as exc:  # noqa: BLE001 — captured for the caller to assert on
                results[idx] = exc
    return results


def _concurrent_successes(results):
    """Count entries from _run_concurrent that did NOT raise."""
    return sum(1 for r in results if not isinstance(r, BaseException))


def _concurrent_error_codes(results):
    """Error codes for the _run_concurrent entries that raised; successes are skipped."""
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get("Error", {}).get("Code"))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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


def _topic_exists(sns, account_id, region, topic_name):
    """Independent read at the SNS destination: does a topic with this name exist?"""
    arn = f"arn:aws:sns:{region}:{account_id}:{topic_name}"
    try:
        sns.get_topic_attributes(TopicArn=arn)
        return True
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "NotFound":
            return False
        raise


def _describe_stack(cfn, name):
    stacks = cfn.describe_stacks(StackName=name).get("Stacks", [])
    assert stacks, f"stack {name} not found"
    return stacks[0]


def _wait_stack_status(cfn, name, timeout_s=180, interval_s=3):
    """Poll DescribeStacks until the stack reaches any terminal status."""
    return _poll_until(
        lambda: _describe_stack(cfn, name),
        lambda stack: stack.get("StackStatus") in _TERMINAL_STACK_STATUSES,
        timeout_s=timeout_s,
        interval_s=interval_s,
        description=f"stack {name} reaching a terminal status",
    )


def _delete_stack_quiet(cfn, name):
    """Teardown: delete the stack and wait for DELETE_COMPLETE; a missing stack is fine."""
    try:
        cfn.delete_stack(StackName=name)
    except ClientError as exc:
        if not (
            exc.response["Error"]["Code"] == "ValidationError"
            and "does not exist" in exc.response["Error"].get("Message", "")
        ):
            raise
        return
    cfn.get_waiter("stack_delete_complete").wait(
        StackName=name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
