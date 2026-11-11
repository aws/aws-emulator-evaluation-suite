"""delete-automated-reasoning-policy-in-use-rejected."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-automated-reasoning-policy-in-use-rejected"
GROUP = "error-semantics"
SERVICES = ["bedrock"]

_POLICY_DOCUMENT = (
    b"All employees must complete safety training annually. Employees who have not "
    b"completed training within the last 12 months may not operate heavy machinery. "
    b"Managers must verify training records before assigning machinery duties."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAutomatedReasoningPolicy is rejected with ValidationException while a build workflow
    on the policy still exists, leaving the policy intact; after the workflow is deleted the same
    call succeeds and the policy then 404s on Get and on a filtered List."""
    bedrock = ctx.client("bedrock")

    name = ctx.unique_name("sim2real-arp-delinuse-")
    policy = bedrock.create_automated_reasoning_policy(
        name=name,
        policyDefinition={},
        tags=[{"key": "sim2real", "value": "arp-delinuse"}],
    )
    policy_arn = policy["policyArn"]
    ctx.on_cleanup(lambda: _safe_delete_policy(bedrock, policy_arn))

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

    # The refusal depends on the build workflow existing, whatever its status, so it is probed
    # at once.
    got = _error(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn))
    expected = ("ValidationException", "There are build workflow that have not been deleted.")
    assert got == expected, (
        f"deleting a policy with an undeleted build workflow: expected {expected!r}, got {got!r}"
    )

    summaries = bedrock.list_automated_reasoning_policies(policyArn=policy_arn).get(
        "automatedReasoningPolicySummaries", []
    )
    assert len(summaries) == 1, f"expected the policy to survive the rejected delete, got {summaries}"
    assert summaries[0]["policyArn"] == policy_arn, (
        f"expected surviving summary to be {policy_arn!r}, got {summaries[0]!r}"
    )

    final = _poll_until(
        lambda: bedrock.get_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=workflow_id
        ),
        lambda r: r["status"] in ("COMPLETED", "FAILED"),
        timeout_s=1800.0,
        interval_s=20.0,
    )
    if final["status"] != "COMPLETED":
        raise AssertionError(
            f"build workflow ended as {final['status']!r} instead of COMPLETED; cannot "
            "exercise the post-completion positive control from this run"
        )

    bedrock.delete_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn, buildWorkflowId=workflow_id, lastUpdatedAt=final["updatedAt"]
    )

    bedrock.delete_automated_reasoning_policy(policyArn=policy_arn)

    # A filtered list on a dead policyArn 404s rather than returning an empty page.
    list_gone = _error(lambda: bedrock.list_automated_reasoning_policies(policyArn=policy_arn))
    list_gone_expected = ("ResourceNotFoundException", "Policy does not exist.")
    assert list_gone == list_gone_expected, (
        f"expected a filtered list on a dead policy to 404 with {list_gone_expected!r}, got {list_gone!r}"
    )

    not_found = _error(lambda: bedrock.get_automated_reasoning_policy(policyArn=policy_arn))
    # GetAutomatedReasoningPolicy's message carries no trailing period, unlike the list's.
    not_found_expected = ("ResourceNotFoundException", "Policy does not exist")
    assert not_found == not_found_expected, (
        f"expected a dead policy to 404 on GetAutomatedReasoningPolicy with "
        f"{not_found_expected!r}, got {not_found!r}"
    )


def _error(fn):
    """The AWS error (code, message) fn raises. Raises AssertionError if fn SUCCEEDS: an
    acceptance where AWS refuses must never read as an error-code mismatch."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message", "")
    raise AssertionError("expected the call to raise a ClientError, but it succeeded")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last!r}")


def _safe_cancel(bedrock, policy_arn: str, workflow_id: str) -> None:
    """Cancel the build workflow; cancelling a finished one is a no-op, a deleted one needs nothing."""
    from botocore.exceptions import ClientError

    try:
        bedrock.cancel_automated_reasoning_policy_build_workflow(
            policyArn=policy_arn, buildWorkflowId=workflow_id
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _safe_delete_policy(bedrock, policy_arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        bedrock.delete_automated_reasoning_policy(policyArn=policy_arn, force=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
