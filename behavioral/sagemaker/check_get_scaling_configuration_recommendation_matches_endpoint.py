"""get-scaling-configuration-recommendation-matches-endpoint."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-scaling-configuration-recommendation-matches-endpoint"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetScalingConfigurationRecommendation with only InferenceRecommendationsJobName
    (no EndpointName or RecommendationId) is refused with ValidationException and its
    exact message, while ListInferenceRecommendationsJobs succeeds on the same client.
    """
    sm = ctx.client("sagemaker")

    missing_job_name = ctx.unique_name("sim2real-sm-irj-missing-")
    code, message, resp = _probe(
        lambda: sm.get_scaling_configuration_recommendation(
            InferenceRecommendationsJobName=missing_job_name
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException, got {code!r} (resp={resp!r})"
    )
    assert message == (
        "Neither RecommendationId or EndpointName were provided in the input. "
        "Please provide a RecommendationId or EndpointName in the request."
    ), f"unexpected GetScalingConfigurationRecommendation message: {message!r}"
    assert resp is None

    # Positive control: the sagemaker client/region wiring itself is healthy -- a
    # legitimate, always-available read against the same resource family succeeds
    # normally, so the ValidationException above is a targeted rejection of this one
    # malformed request, not a blanket failure to reach the service at all.
    control = sm.list_inference_recommendations_jobs(MaxResults=1)
    assert "InferenceRecommendationsJobs" in control, (
        f"expected InferenceRecommendationsJobs in a healthy list response, got keys "
        f"{sorted(control)!r}"
    )


def _probe(fn):
    from botocore.exceptions import ClientError

    try:
        return None, None, fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message"), None


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
