"""resource-evaluation-summary-reflects-proactive-evaluation."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "resource-evaluation-summary-reflects-proactive-evaluation"
GROUP = "data-plane"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c4", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """GetResourceEvaluationSummary for a PROACTIVE StartResourceEvaluation of an S3 bucket echoes its id,
    mode and resource, and with no PROACTIVE rule for the type it ends FAILED with the exact
    FailureReason and Compliance NOT_APPLICABLE."""
    config = ctx.client("config")

    resource_id = ctx.unique_name("sim2real-proactive-bucket-")
    resource_config = json.dumps({"BucketName": resource_id})
    resource_details = {
        "ResourceId": resource_id,
        "ResourceType": "AWS::S3::Bucket",
        "ResourceConfiguration": resource_config,
        "ResourceConfigurationSchemaType": "CFN_RESOURCE_SCHEMA",
    }

    resp = config.start_resource_evaluation(EvaluationMode="PROACTIVE", ResourceDetails=resource_details)
    evaluation_id = resp["ResourceEvaluationId"]

    def _summary():
        return config.get_resource_evaluation_summary(ResourceEvaluationId=evaluation_id)

    final = _poll_until(_summary, lambda s: s["EvaluationStatus"]["Status"] in ("SUCCEEDED", "FAILED"), timeout_s=60, interval_s=2)

    # Regardless of terminal state, the evaluation's own identity/echo fields must be
    # faithfully carried through by GetResourceEvaluationSummary.
    assert final["ResourceEvaluationId"] == evaluation_id, (
        f"expected ResourceEvaluationId {evaluation_id!r}, got {final.get('ResourceEvaluationId')!r}"
    )
    assert final["EvaluationMode"] == "PROACTIVE", (
        f"expected EvaluationMode 'PROACTIVE', got {final.get('EvaluationMode')!r}"
    )
    assert final["ResourceDetails"]["ResourceId"] == resource_id, (
        f"expected echoed ResourceId {resource_id!r}, got {final['ResourceDetails'].get('ResourceId')!r}"
    )
    assert final["ResourceDetails"]["ResourceType"] == "AWS::S3::Bucket", (
        f"expected echoed ResourceType 'AWS::S3::Bucket', got {final['ResourceDetails'].get('ResourceType')!r}"
    )

    # A bare account has no PROACTIVE rule for AWS::S3::Bucket, so the state
    # machine must deterministically land on FAILED with this exact reason --
    # not SUCCEEDED, which would mean a rule was found that was never created.
    status = final["EvaluationStatus"]["Status"]
    assert status == "FAILED", (
        f"a bare account with no PROACTIVE rule for AWS::S3::Bucket must terminate "
        f"the evaluation FAILED, got {status!r} ({final['EvaluationStatus']!r})"
    )
    assert final["EvaluationStatus"].get("FailureReason") == (
        "No Config rule is enabled in proactive mode for the given resource type."
    ), f"unexpected FailureReason: {final['EvaluationStatus'].get('FailureReason')!r}"
    assert final["Compliance"] == "NOT_APPLICABLE", (
        f"expected Compliance 'NOT_APPLICABLE' even in the FAILED state, got {final.get('Compliance')!r}"
    )


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
