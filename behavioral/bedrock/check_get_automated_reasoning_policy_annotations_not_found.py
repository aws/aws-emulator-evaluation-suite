"""get-automated-reasoning-policy-annotations-not-found."""
from __future__ import annotations


from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-automated-reasoning-policy-annotations-not-found"
GROUP = "error-semantics"
SERVICES = ["bedrock"]

# A valid-shaped (but never-issued) UUIDv4 matching buildWorkflowId's required
# pattern, so the negative call fails on "not found" rather than "malformed".
_NEVER_ISSUED_WORKFLOW_ID = "00000000-0000-4000-8000-000000000000"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetAutomatedReasoningPolicyAnnotations for a nonexistent build workflow returns
    ResourceNotFoundException, while the same call and GetAutomatedReasoningPolicyBuildWorkflow
    succeed for a real in-flight workflow."""
    bedrock = ctx.client("bedrock")
    policy_arn = _create_ar_policy(ctx)
    workflow_id = _start_ingest_build_workflow(
        ctx,
        policy_arn,
        "Refunds are only permitted within 30 days of purchase. All refund "
        "requests over $500 must be approved by a manager before being issued.",
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: bedrock.cancel_automated_reasoning_policy_build_workflow(
                policyArn=policy_arn, buildWorkflowId=workflow_id
            )
        )
    )

    # positive control: the real, freshly issued workflow id is recognized by the
    # sibling Get-build-workflow operation
    wf = bedrock.get_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn, buildWorkflowId=workflow_id
    )
    assert wf["buildWorkflowId"] == workflow_id, (
        f"expected buildWorkflowId {workflow_id!r}, got {wf.get('buildWorkflowId')!r}"
    )

    # positive control (same operation under test): the real, freshly issued
    # workflow id is recognized by GetAutomatedReasoningPolicyAnnotations itself,
    # so the negative below cannot be "rejects every call" wearing a not-found mask
    annotations_resp = bedrock.get_automated_reasoning_policy_annotations(
        policyArn=policy_arn, buildWorkflowId=workflow_id
    )
    assert annotations_resp["buildWorkflowId"] == workflow_id, (
        f"expected buildWorkflowId {workflow_id!r}, got {annotations_resp.get('buildWorkflowId')!r}"
    )
    assert annotations_resp["policyArn"] == policy_arn, (
        f"expected policyArn {policy_arn!r}, got {annotations_resp.get('policyArn')!r}"
    )

    # negative: a never-issued (but pattern-valid) workflow id under the same,
    # real policy is not found
    code, message = _error(
        lambda: bedrock.get_automated_reasoning_policy_annotations(
            policyArn=policy_arn, buildWorkflowId=_NEVER_ISSUED_WORKFLOW_ID
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    expected = "Build WorkflowExecution not found"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _create_ar_policy(ctx) -> str:
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-bedrock-arpwf-")
    created = bedrock.create_automated_reasoning_policy(
        name=name, tags=[{"key": "sim2real-check", "value": CHECK}]
    )
    policy_arn = created["policyArn"]
    # force: the policy still holds the build workflow this check started.
    ctx.on_cleanup(
        lambda: _safe(lambda: bedrock.delete_automated_reasoning_policy(policyArn=policy_arn, force=True))
    )
    return policy_arn


def _start_ingest_build_workflow(ctx, policy_arn: str, text: str) -> str:
    bedrock = ctx.client("bedrock")
    resp = bedrock.start_automated_reasoning_policy_build_workflow(
        policyArn=policy_arn,
        buildWorkflowType="INGEST_CONTENT",
        sourceContent={
            "workflowContent": {
                "documents": [
                    {
                        "document": text.encode("utf-8"),
                        "documentContentType": "txt",
                        "documentName": "policy-source.txt",
                    }
                ]
            }
        },
    )
    return resp["buildWorkflowId"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _safe(fn) -> None:
    """Run a teardown call; return only when its resource is already gone."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
