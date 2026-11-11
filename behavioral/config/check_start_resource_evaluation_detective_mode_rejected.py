"""start-resource-evaluation-detective-mode-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "start-resource-evaluation-detective-mode-rejected"
GROUP = "data-plane"
SERVICES = ["config"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartResourceEvaluation rejects EvaluationMode=DETECTIVE with InvalidParameterValueException and
    mints no ResourceEvaluationId, while the same request with PROACTIVE succeeds and reads back
    through GetResourceEvaluationSummary."""
    config = ctx.client("config")

    resource_id = ctx.unique_name("sim2real-evalmode-")
    resource_details = {
        "ResourceId": resource_id,
        "ResourceType": "AWS::S3::Bucket",
        "ResourceConfiguration": json.dumps({"BucketName": resource_id}),
        "ResourceConfigurationSchemaType": "CFN_RESOURCE_SCHEMA",
    }

    # A ListResourceEvaluations entry carries only ResourceEvaluationId and
    # EvaluationStartTimestamp -- it does not echo ResourceDetails, so absence for
    # this resource id cannot be read back by matching a field that is never present.
    # Use an independent-read set diff instead: no new ResourceEvaluationId at all.
    baseline_ids = {
        r["ResourceEvaluationId"]
        for r in config.list_resource_evaluations(Limit=100).get(
            "ResourceEvaluations", []
        )
    }

    code, message = _error(
        lambda: config.start_resource_evaluation(
            ResourceDetails=resource_details, EvaluationMode="DETECTIVE"
        )
    )
    assert code == "InvalidParameterValueException", (
        f"expected InvalidParameterValueException for EvaluationMode=DETECTIVE, "
        f"got {code!r}"
    )
    expected_message = (
        "DETECTIVE Evaluation Mode is not supported. "
        "The supported Evaluation Modes are: [PROACTIVE]."
    )
    assert message == expected_message, (
        f"expected message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the rejected call minted no new resource evaluation at all.
    after_reject_ids = {
        r["ResourceEvaluationId"]
        for r in config.list_resource_evaluations(Limit=100).get(
            "ResourceEvaluations", []
        )
    }
    # The list is account-wide, so a concurrent caller's evaluation may appear; none of the new
    # ids may describe this check's resource.
    assert after_reject_ids == baseline_ids or all(
        config.get_resource_evaluation_summary(ResourceEvaluationId=new_id)["ResourceDetails"][
            "ResourceId"
        ]
        != resource_id
        for new_id in after_reject_ids - baseline_ids
    ), (
        f"DETECTIVE call must mint nothing for {resource_id!r}; new ids "
        f"{after_reject_ids - baseline_ids} appeared"
    )

    # Positive control: PROACTIVE is accepted for the identical resource details.
    started = config.start_resource_evaluation(
        ResourceDetails=resource_details, EvaluationMode="PROACTIVE"
    )
    evaluation_id = started["ResourceEvaluationId"]
    assert evaluation_id, f"PROACTIVE call minted no ResourceEvaluationId: {started!r}"

    # Terminal read: an independent operation confirms Config actually holds this
    # evaluation, for the mode we asked for and the resource we described.
    summary = config.get_resource_evaluation_summary(
        ResourceEvaluationId=evaluation_id
    )
    assert summary["EvaluationMode"] == "PROACTIVE", (
        f"expected EvaluationMode=PROACTIVE on the independent read, "
        f"got {summary.get('EvaluationMode')!r}"
    )
    assert summary["ResourceDetails"]["ResourceId"] == resource_id, (
        f"expected ResourceDetails.ResourceId={resource_id!r} on the independent "
        f"read, got {summary.get('ResourceDetails')!r}"
    )


def _error(fn):
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message", "")
        raise
    raise AssertionError(f"expected a rejection, call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
