"""scaling-configuration-recommendation-for-live-endpoint."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scaling-configuration-recommendation-for-live-endpoint"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetScalingConfigurationRecommendation without EndpointName or RecommendationId is refused with
    ValidationException, and with an EndpointName for an unknown job with ResourceNotFound (exact messages);
    DescribeInferenceRecommendationsJob also returns ResourceNotFound for that job.
    """
    sm = ctx.client("sagemaker")

    missing_job_name = ctx.unique_name("sim2real-irj-missing-")

    shape_code, shape_message = _error(
        lambda: sm.get_scaling_configuration_recommendation(InferenceRecommendationsJobName=missing_job_name)
    )
    assert shape_code == "ValidationException", (
        f"expected ValidationException when neither EndpointName nor RecommendationId is "
        f"supplied, got {shape_code!r}"
    )
    expected_shape = (
        "Neither RecommendationId or EndpointName were provided in the input. "
        "Please provide a RecommendationId or EndpointName in the request."
    )
    assert shape_message == expected_shape, f"expected message {expected_shape!r}, got {shape_message!r}"

    missing_endpoint_name = ctx.unique_name("sim2real-irj-missing-ep-")
    lookup_code, lookup_message = _error(
        lambda: sm.get_scaling_configuration_recommendation(
            InferenceRecommendationsJobName=missing_job_name,
            EndpointName=missing_endpoint_name,
        )
    )
    assert lookup_code == "ResourceNotFound", (
        f"expected ResourceNotFound once a target field is supplied for a job/endpoint "
        f"pair that was never created, got {lookup_code!r}"
    )
    expected_lookup = f"Inference recommendations job {missing_job_name} was not found."
    assert lookup_message == expected_lookup, f"expected message {expected_lookup!r}, got {lookup_message!r}"
    assert lookup_code != shape_code, "the two boundaries collapsed to the same error code"

    # Effect absent: the rejected lookup must not have implicitly registered a job under
    # that name as a side effect.
    describe_code, describe_message = _error(
        lambda: sm.describe_inference_recommendations_job(JobName=missing_job_name)
    )
    assert describe_code == "ResourceNotFound", (
        f"GetScalingConfigurationRecommendation appears to have created a job as a side "
        f"effect of a rejected request; DescribeInferenceRecommendationsJob returned "
        f"{describe_code!r} instead of ResourceNotFound"
    )
    expected_describe = f"Inference recommendations job {missing_job_name} for {ctx.account} not found."
    assert describe_message == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_message!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
