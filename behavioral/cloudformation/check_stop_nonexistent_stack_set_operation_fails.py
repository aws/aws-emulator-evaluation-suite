"""stop-nonexistent-stack-set-operation-fails."""
from __future__ import annotations

import json
import time
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "stop-nonexistent-stack-set-operation-fails"
GROUP = 'stack_sets'
SERVICES = ['cloudformation']


def _error(fn):
    """(Error.Code, Error.Message) of the rejection fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")

def _topic_template(topic_name=None, extra_tag=None):
    props = {}
    if topic_name:
        props["TopicName"] = topic_name
    if extra_tag:
        props["Tags"] = [{"Key": "probe", "Value": extra_tag}]
    return json.dumps({
        "Resources": {"Topic": {"Type": "AWS::SNS::Topic", "Properties": props}},
        "Outputs": {"TopicArn": {"Value": {"Ref": "Topic"}}},
    })


def _wait_terminal(cf, name, op_id, timeout_s=120, interval_s=3):
    """Poll DescribeStackSetOperation until Status is terminal; return it."""
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = cf.describe_stack_set_operation(
            StackSetName=name, OperationId=op_id
        )["StackSetOperation"]["Status"]
        if status in ("SUCCEEDED", "FAILED", "STOPPED"):
            return status
        time.sleep(interval_s)
    raise AssertionError(f"operation {op_id} never reached a terminal state, last={status}")


def _delete_stack_set(cf, name, timeout_s=60, interval_s=3):
    """Delete the stack set, tolerating a still-settling prior operation."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            cf.delete_stack_set(StackSetName=name)
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "OperationInProgressException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StopStackSetOperation on a made-up OperationId fails with OperationNotFoundException
    "Operation not found", while on a real OperationId the same stack set issued it never
    answers OperationNotFoundException."""
    cf = ctx.client("cloudformation")
    name = ctx.unique_name("sim2real-behav-ss-stopop-")
    cf.create_stack_set(StackSetName=name, TemplateBody=_topic_template())
    ctx.on_cleanup(lambda: _delete_stack_set(cf, name))

    real_op_id = cf.update_stack_set(
        StackSetName=name, TemplateBody=_topic_template(extra_tag="v2")
    )["OperationId"]
    try:
        cf.stop_stack_set_operation(StackSetName=name, OperationId=real_op_id)
    except ClientError as exc:
        assert exc.response["Error"]["Code"] != "OperationNotFoundException", (
            f"a real OperationId ({real_op_id!r}) this StackSet issued must not be "
            f"reported not-found, got {exc.response['Error']!r}"
        )
    _wait_terminal(cf, name, real_op_id)

    bogus_op_id = ctx.unique_name("sim2real-behav-op-")
    error = _error(
        lambda: cf.stop_stack_set_operation(StackSetName=name, OperationId=bogus_op_id)
    )
    expected = ("OperationNotFoundException", "Operation not found")
    assert error == expected, f"expected {expected!r}, got {error!r}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
