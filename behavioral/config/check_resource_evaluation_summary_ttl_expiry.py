"""resource-evaluation-summary-ttl-expiry."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "resource-evaluation-summary-ttl-expiry"
GROUP = "visibility-timeout-ttl"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A PROACTIVE StartResourceEvaluation leaves IN_PROGRESS within 60 s and its summary echoes
    the evaluation id and mode; SUCCEEDED reports Compliance NOT_APPLICABLE and FAILED carries a
    FailureReason."""
    config = ctx.client("config")
    resource_id = ctx.unique_name("sim2real-behav-eval-")

    start = config.start_resource_evaluation(
        ResourceDetails={
            "ResourceId": resource_id,
            "ResourceType": "AWS::S3::Bucket",
            "ResourceConfiguration": json.dumps({"BucketName": resource_id}),
            "ResourceConfigurationSchemaType": "CFN_RESOURCE_SCHEMA",
        },
        EvaluationMode="PROACTIVE",
    )
    evaluation_id = start["ResourceEvaluationId"]

    final_status = None
    deadline = time.monotonic() + 60.0
    while time.monotonic() < deadline:
        summary = config.get_resource_evaluation_summary(ResourceEvaluationId=evaluation_id)
        status = summary["EvaluationStatus"]["Status"]
        if status != "IN_PROGRESS":
            final_status = status
            final_summary = summary
            break
        time.sleep(2)

    assert final_status is not None, (
        f"evaluation {evaluation_id} never left IN_PROGRESS within 60s"
    )
    assert final_status in ("SUCCEEDED", "FAILED"), (
        f"terminal status must be SUCCEEDED or FAILED, got {final_status!r}"
    )
    assert final_summary["ResourceEvaluationId"] == evaluation_id, (
        f"summary must echo the started evaluation id {evaluation_id!r}, got "
        f"{final_summary['ResourceEvaluationId']!r}"
    )
    assert final_summary["EvaluationMode"] == "PROACTIVE", (
        f"summary must echo EvaluationMode=PROACTIVE, got "
        f"{final_summary.get('EvaluationMode')!r}"
    )

    if final_status == "SUCCEEDED":
        # MEASURED: no PROACTIVE-mode rule targets AWS::S3::Bucket in a bare account, so a SUCCEEDED
        # evaluation's compliance is deterministically NOT_APPLICABLE. Without this, a target that
        # always answers SUCCEEDED with no compliance verdict at all would still satisfy the
        # accept-set above.
        assert final_summary["Compliance"] == "NOT_APPLICABLE", (
            f"a SUCCEEDED evaluation with no PROACTIVE rule for the resource type "
            f"must report Compliance NOT_APPLICABLE, got "
            f"{final_summary.get('Compliance')!r}"
        )
    else:
        assert final_summary["EvaluationStatus"].get("FailureReason"), (
            "a FAILED evaluation must carry a concrete, non-empty FailureReason, "
            "not a silent failure"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
