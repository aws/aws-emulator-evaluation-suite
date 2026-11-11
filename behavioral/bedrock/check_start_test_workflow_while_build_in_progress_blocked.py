"""start-test-workflow-while-build-in-progress-blocked."""
from __future__ import annotations

import time
from datetime import datetime, timezone

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-test-workflow-while-build-in-progress-blocked"
GROUP = "error-semantics"
SERVICES = ["bedrock"]

_POLICY_DOCUMENT = (
    b"All employees must complete safety training annually. Employees who have not "
    b"completed training within the last 12 months may not operate heavy machinery. "
    b"Managers must verify training records before assigning machinery duties."
)


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartAutomatedReasoningPolicyTestWorkflow against a build workflow not yet COMPLETED returns
    ValidationException naming that workflow; once it reaches COMPLETED the same call succeeds."""
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-arp-tw-")
    policy = bedrock.create_automated_reasoning_policy(
        name=name,
        policyDefinition={},
        tags=[{"key": "sim2real", "value": "start-test-workflow-while-build-in-progress-blocked"}],
    )
    policy_arn = policy["policyArn"]
    ctx.on_cleanup(lambda: _delete_policy(bedrock, policy_arn))

    test_case = bedrock.create_automated_reasoning_policy_test_case(
        policyArn=policy_arn,
        guardContent="Employees who completed training 13 months ago may operate heavy machinery.",
        expectedAggregatedFindingsResult="SATISFIABLE",
    )
    test_case_id = test_case["testCaseId"]
    ctx.on_cleanup(lambda: _delete_test_case(bedrock, policy_arn, test_case_id))

    build = bedrock.start_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn,
        buildWorkflowType="INGEST_CONTENT",
        sourceContent={
            "workflowContent": {
                "documents": [
                    {
                        "document": _POLICY_DOCUMENT,
                        "documentContentType": "txt",
                        "documentName": "safety-policy.txt",
                    }
                ]
            }
        },
    )
    workflow_id = build["buildWorkflowId"]
    ctx.on_cleanup(lambda: _safe_cancel(bedrock, policy_arn, workflow_id))

    # The build runs for minutes on AWS, so the probe goes out at once, while it is in progress;
    # the read after the probe proves the build was not yet COMPLETED when it was refused.
    probed_at = datetime.now(timezone.utc)
    code, message = _error_code_and_message(
        lambda: bedrock.start_automated_reasoning_policy_test_workflow(
            policyArn=policy_arn, buildWorkflowId=workflow_id
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a test-workflow start against a build "
        f"workflow not yet COMPLETED, got {code!r} ({message!r})"
    )
    expected = f"Build workflow: {workflow_id} is not in COMPLETED status"
    assert message == expected, (
        f"expected the ValidationException message {expected!r}, got {message!r}"
    )

    # The build must have been non-terminal at the probe: still running, or completed after it.
    wf = bedrock.get_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn, buildWorkflowId=workflow_id
    )
    assert wf["status"] != "FAILED", f"the build workflow failed: {wf!r}"
    if wf["status"] == "COMPLETED":
        # updatedAt may carry whole seconds only, so compare against the probe's second.
        assert wf["updatedAt"] >= probed_at.replace(microsecond=0), (
            f"expected the build workflow to still be non-terminal when the rejection was "
            f"observed, but it completed at {wf['updatedAt']!r}, before the probe at {probed_at!r}"
        )

    final_status = _poll_until(
        lambda: bedrock.get_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=workflow_id
        )["status"],
        lambda s: s in ("COMPLETED", "FAILED"),
        timeout_s=_budget_s(ctx, 1800.0),
        ctx=ctx,
        interval_s=2.0,
    )
    if final_status != "COMPLETED":
        raise AssertionError(
            f"build workflow ended as {final_status} instead of COMPLETED; cannot "
            "exercise the post-completion positive control from this run"
        )
    resp = bedrock.start_automated_reasoning_policy_test_workflow(
        policyArn=policy_arn, buildWorkflowId=workflow_id
    )
    assert resp["policyArn"] == policy_arn, (
        f"expected the restored test-workflow start to echo policyArn {policy_arn!r}, "
        f"got {resp.get('policyArn')!r}"
    )


def _error_code_and_message(fn):
    try:
        fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message")
    raise AssertionError("expected the call to raise a ClientError, but it succeeded")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0, ctx=None):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(min(interval_s, max(0.0, deadline - time.monotonic())))
    if ctx is not None and _budget_spent(ctx):
        raise TimeoutError(f"condition (last={last!r}): the run budget ended first; not graded")
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _safe_cancel(bedrock, policy_arn: str, workflow_id: str) -> None:
    try:
        bedrock.cancel_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=workflow_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_policy(bedrock, policy_arn: str) -> None:
    _retry_while_in_use(
        lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn, force=True)
    )


def _delete_test_case(bedrock, policy_arn: str, test_case_id: str) -> None:
    def _delete() -> None:
        current = bedrock.get_automated_reasoning_policy_test_case(
            policyArn=policy_arn, testCaseId=test_case_id
        )["testCase"]
        bedrock.delete_automated_reasoning_policy_test_case(
            policyArn=policy_arn, testCaseId=test_case_id, lastUpdatedAt=current["updatedAt"]
        )

    _retry_while_in_use(_delete)


def _retry_while_in_use(fn, timeout_s: float = 900.0, interval_s: float = 2.0) -> None:
    """Retry a teardown call while the positive-control test workflow still holds the
    policy (ResourceInUseException); raise once the deadline passes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
