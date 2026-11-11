"""e2e-resource-evaluation-summary-flow."""
from __future__ import annotations

import json
import secrets
import time

from behavioral_harness import tags

CHECK = "e2e-resource-evaluation-summary-flow"
GROUP = "e2e"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c2", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartResourceEvaluation in PROACTIVE mode for a proposed S3 bucket yields a summary echoing the
    submitted mode, evaluation context and resource, and ListResourceEvaluations filtered by that
    context returns the evaluation."""
    config = ctx.client("config")

    resource_id = ctx.unique_name("sim2real-reseval-bucket-").lower()
    eval_context_id = ctx.unique_name("sim2real-reseval-ctx-")
    client_token = secrets.token_hex(32)  # 64 chars, meets the >=64 length requirement

    resource_configuration = json.dumps({"BucketName": resource_id})

    start = config.start_resource_evaluation(
        ClientToken=client_token,
        EvaluationMode="PROACTIVE",
        EvaluationContext={"EvaluationContextIdentifier": eval_context_id},
        ResourceDetails={
            "ResourceId": resource_id,
            "ResourceType": "AWS::S3::Bucket",
            "ResourceConfiguration": resource_configuration,
            "ResourceConfigurationSchemaType": "CFN_RESOURCE_SCHEMA",
        },
    )
    evaluation_id = start["ResourceEvaluationId"]

    summary = _poll_until(
        lambda: config.get_resource_evaluation_summary(ResourceEvaluationId=evaluation_id),
        lambda s: s["EvaluationStatus"]["Status"] != "IN_PROGRESS",
        timeout_s=60,
        interval_s=3,
    )
    status = summary["EvaluationStatus"]["Status"]
    assert status in ("SUCCEEDED", "FAILED"), summary["EvaluationStatus"]
    if status == "FAILED":
        # Even a failed evaluation must report *why* -- the summary is still
        # required to be internally consistent with what was submitted.
        assert summary["EvaluationStatus"].get("FailureReason"), (
            f"FAILED evaluation has no FailureReason: {summary['EvaluationStatus']}"
        )
    else:
        assert summary["Compliance"] in (
            "COMPLIANT", "NON_COMPLIANT", "NOT_APPLICABLE", "INSUFFICIENT_DATA"
        ), summary
    assert summary["EvaluationMode"] == "PROACTIVE", (
        f"expected EvaluationMode PROACTIVE, got {summary.get('EvaluationMode')!r}"
    )
    assert summary["EvaluationContext"]["EvaluationContextIdentifier"] == eval_context_id, (
        f"expected EvaluationContextIdentifier {eval_context_id!r}, got "
        f"{summary['EvaluationContext'].get('EvaluationContextIdentifier')!r}"
    )
    assert summary["ResourceDetails"]["ResourceId"] == resource_id, (
        f"expected ResourceId {resource_id!r}, got {summary['ResourceDetails'].get('ResourceId')!r}"
    )
    assert summary["ResourceDetails"]["ResourceType"] == "AWS::S3::Bucket", (
        f"expected ResourceType AWS::S3::Bucket, got {summary['ResourceDetails'].get('ResourceType')!r}"
    )

    listed = _poll_until(
        lambda: config.list_resource_evaluations(
            Filters={"EvaluationContextIdentifier": eval_context_id}
        )["ResourceEvaluations"],
        lambda rows: any(r["ResourceEvaluationId"] == evaluation_id for r in rows),
        timeout_s=60,
        interval_s=5,
    )
    match = next(r for r in listed if r["ResourceEvaluationId"] == evaluation_id)
    assert set(match) == {"ResourceEvaluationId", "EvaluationStartTimestamp"}, (
        f"expected a ListResourceEvaluations entry with exactly ResourceEvaluationId and "
        f"EvaluationStartTimestamp (no EvaluationMode -- the mode lives entirely in the "
        f"Filters vocabulary), got {sorted(match)!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last observed: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
