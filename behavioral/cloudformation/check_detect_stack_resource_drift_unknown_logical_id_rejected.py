"""detect-stack-resource-drift-unknown-logical-id-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "detect-stack-resource-drift-unknown-logical-id-rejected"
GROUP = "drift-detection"
SERVICES = ["cloudformation"]


def _template(logical_id: str) -> str:
    return json.dumps({
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {logical_id: {"Type": "AWS::SNS::Topic", "Properties": {}}},
    })


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _wait_stack(cfn, stack_name, terminal, timeout_s=240.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        if last in terminal:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"stack {stack_name!r} did not reach {terminal} in {timeout_s}s (last={last!r})")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DetectStackResourceDrift on a logical id the stack's template never declared is
    rejected with ValidationError; the same call for a real resource succeeds."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-driftid-")
    real_id = "Topic"

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_template(real_id),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["StackId"]
    ctx.on_cleanup(lambda: cfn.delete_stack(StackName=stack_name))
    created = _wait_stack(cfn, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})
    assert created == "CREATE_COMPLETE", f"prerequisite stack {stack_name!r} reached {created!r}"

    # POSITIVE CONTROL: a logical id the template actually declares is accepted.
    control = cfn.detect_stack_resource_drift(
        StackName=stack_name, LogicalResourceId=real_id
    )["StackResourceDrift"]
    assert control["LogicalResourceId"] == real_id, (
        f"expected drift detail for {real_id!r}, got {control['LogicalResourceId']!r}"
    )
    assert control["StackResourceDriftStatus"] == "IN_SYNC", (
        f"a freshly created, untouched resource must be IN_SYNC, got {control['StackResourceDriftStatus']!r}"
    )

    # ONE thing broken: a logical id the template never declared.
    unknown_id = "NoSuchLogicalId"
    assert unknown_id not in json.loads(_template(real_id))["Resources"], (
        "the 'unknown' logical id must not be in the template"
    )
    code, message = _error(
        lambda: cfn.detect_stack_resource_drift(StackName=stack_name, LogicalResourceId=unknown_id)
    )
    assert code == "ValidationError", (
        f"DetectStackResourceDrift for an unknown logical id answered {code!r}, expected ValidationError"
    )
    assert message == f"Resource {unknown_id} does not exist in stack {stack_id}", (
        f"unexpected ValidationError message {message!r}"
    )

    # The effect is absent: the real resource's drift status is unaffected by the rejected call.
    recheck = cfn.detect_stack_resource_drift(
        StackName=stack_name, LogicalResourceId=real_id
    )["StackResourceDrift"]
    assert recheck["StackResourceDriftStatus"] == "IN_SYNC", (
        f"the rejected call for an unknown id must not disturb the real resource's drift status, "
        f"got {recheck['StackResourceDriftStatus']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
