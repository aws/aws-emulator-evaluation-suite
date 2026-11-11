"""op-contract-setStackPolicy."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-setStackPolicy"
GROUP = "error-semantics"
SERVICES = ["cloudformation"]


@tags("axis:rejection", "cap:c3", "cap:c4", "concern:deploy", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetStackPolicy round-trips the policy; a Deny Update:* policy blocks an update that succeeds
    without it and keeps it off the bucket, lifting the Deny lets it complete, and a malformed
    policy is rejected with ValidationError."""
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-cfn-setpolicy-")

    stack_id = cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_bucket_template("v1"),
        Tags=[{"Key": "sim2real", "Value": stack_name}],
    )["StackId"]
    ctx.on_cleanup(lambda: _teardown_stack(cfn, stack_id))
    _wait_for_stack_status(ctx, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE"})

    # --- positive control: this class of update succeeds with no stack policy in force ---
    cfn.update_stack(StackName=stack_name, TemplateBody=_bucket_template("v1b"))
    status = _wait_for_stack_status(
        ctx, stack_name, {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED"}
    )
    assert status == "UPDATE_COMPLETE", f"positive-control update must succeed with no stack policy, got {status}"
    assert _bucket_env_tag(ctx, stack_name) == "v1b", "positive-control update did not reach the bucket"

    # --- SetStackPolicy / GetStackPolicy round-trip, exact body ---
    deny_policy = {
        "Statement": [{"Effect": "Deny", "Action": "Update:*", "Principal": "*", "Resource": "*"}]
    }
    cfn.set_stack_policy(StackName=stack_name, StackPolicyBody=json.dumps(deny_policy))
    got = json.loads(cfn.get_stack_policy(StackName=stack_name)["StackPolicyBody"])
    assert got == deny_policy, f"stack policy round-trip mismatch: {got} != {deny_policy}"

    # --- break: the identical kind of update is now denied ---
    cfn.update_stack(StackName=stack_name, TemplateBody=_bucket_template("v2"))
    status = _wait_for_stack_status(
        ctx,
        stack_name,
        {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED"},
        timeout_s=300,
    )
    assert status == "UPDATE_ROLLBACK_COMPLETE", (
        f"update should have been rolled back by the Deny Update:* stack policy, got {status}"
    )

    events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    reasons = [
        e.get("ResourceStatusReason")
        for e in events
        if e["LogicalResourceId"] == "Bucket" and e["ResourceStatus"] == "UPDATE_FAILED"
    ]
    denied_action = deny_policy["Statement"][0]["Action"]
    denied_resource = deny_policy["Statement"][0]["Resource"]
    expected_reason = (
        f"Action denied by stack policy: Statement [#1] does not allow [{denied_action}] "
        f"for resource [{denied_resource}];"
    )
    assert reasons == [expected_reason], (
        f"the Bucket's UPDATE_FAILED events carry {reasons!r}, expected [{expected_reason!r}]"
    )

    # --- effect absent: the denied change never reached the bucket itself ---
    assert _bucket_env_tag(ctx, stack_name) == "v1b", "the denied update must not have reached the bucket"

    # --- restore: lift the deny, and the identical update now completes ---
    allow_policy = {
        "Statement": [{"Effect": "Allow", "Action": "Update:*", "Principal": "*", "Resource": "*"}]
    }
    cfn.set_stack_policy(StackName=stack_name, StackPolicyBody=json.dumps(allow_policy))
    cfn.update_stack(StackName=stack_name, TemplateBody=_bucket_template("v2"))
    status = _wait_for_stack_status(
        ctx, stack_name, {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED"}
    )
    assert status == "UPDATE_COMPLETE", f"identical update must succeed once the deny policy is lifted, got {status}"
    assert _bucket_env_tag(ctx, stack_name) == "v2", "restored update did not reach the bucket"

    # --- always-invalid input: a malformed policy document is rejected ---
    code, message = _error(
        lambda: cfn.set_stack_policy(StackName=stack_name, StackPolicyBody="{not valid json")
    )
    assert code == "ValidationError", f"expected ValidationError for malformed policy, got {code}"
    assert message == "Error validating stack policy: Invalid stack policy", (
        f"unexpected ValidationError message {message!r}"
    )


def _bucket_template(tag_value: str) -> str:
    return json.dumps(
        {
            "Resources": {
                "Bucket": {
                    "Type": "AWS::S3::Bucket",
                    "Properties": {"Tags": [{"Key": "env", "Value": tag_value}]},
                }
            }
        }
    )


def _bucket_env_tag(ctx, stack_name: str) -> str:
    cfn = ctx.client("cloudformation")
    bucket_name = cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId="Bucket"
    )["StackResourceDetail"]["PhysicalResourceId"]
    tag_set = ctx.client("s3").get_bucket_tagging(Bucket=bucket_name)["TagSet"]
    return next(t["Value"] for t in tag_set if t["Key"] == "env")


def _error(fn):
    """Call fn(); return botocore (Error.Code, Error.Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        err = e.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _wait_for_stack_status(ctx, stack_name, terminal_statuses, timeout_s=180.0, interval_s=3.0):
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        last = resp["Stacks"][0]["StackStatus"]
        if last in terminal_statuses:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"stack {stack_name} did not reach {terminal_statuses} in {timeout_s}s (last={last})"
    )


def _teardown_stack(cfn, stack_id: str, *, timeout_s: float = 600.0) -> None:
    """Delete the stack by StackId and poll to DELETE_COMPLETE; DELETE_FAILED or a timeout raises."""
    prior = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]["StackStatus"]
    if prior == "DELETE_COMPLETE":
        return
    cfn.delete_stack(StackName=stack_id)
    deadline = time.monotonic() + timeout_s
    moved = False
    while True:
        stack = cfn.describe_stacks(StackName=stack_id)["Stacks"][0]
        status = stack["StackStatus"]
        moved = moved or status != prior
        if status == "DELETE_COMPLETE":
            return
        if status == "DELETE_FAILED" and moved:
            raise AssertionError(f"stack {stack_id} teardown ended DELETE_FAILED: {stack.get('StackStatusReason')!r}")
        if time.monotonic() > deadline:
            raise AssertionError(f"stack {stack_id} still {status} {timeout_s}s after DeleteStack")
        time.sleep(5.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
