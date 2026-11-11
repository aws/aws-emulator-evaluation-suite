"""get-scaling-configuration-recommendation-for-valid-endpoint."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-scaling-configuration-recommendation-for-valid-endpoint"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetScalingConfigurationRecommendation naming a job that was never created returns ResourceNotFound with its
    exact message, DescribeInferenceRecommendationsJob returns ResourceNotFound for that name, and
    ListInferenceRecommendationsJobs succeeds on the same client.

    https://docs.aws.amazon.com/sagemaker/latest/APIReference/API_GetScalingConfigurationRecommendation.html
    """
    sm = ctx.client("sagemaker")
    bogus_job_name = ctx.unique_name("sim2real-sm-irj-")
    bogus_endpoint_name = ctx.unique_name("sim2real-sm-ep-")

    code, message = _error(
        lambda: sm.get_scaling_configuration_recommendation(
            InferenceRecommendationsJobName=bogus_job_name,
            EndpointName=bogus_endpoint_name,
        )
    )
    assert code == "ResourceNotFound", (
        f"expected ResourceNotFound for a scaling recommendation referencing a job that was "
        f"never created, got {code!r}"
    )
    assert message == f"Inference recommendations job {bogus_job_name} was not found.", f"unexpected GetScalingConfigurationRecommendation message: {message!r}"

    # Effect absent: the rejected call must not have implicitly registered/created a job under
    # that name as a side effect.
    code, message = _error(lambda: sm.describe_inference_recommendations_job(JobName=bogus_job_name))
    assert code == "ResourceNotFound", (
        "GetScalingConfigurationRecommendation appears to have created a job as a side effect "
        f"of a rejected request; DescribeInferenceRecommendationsJob returned {code!r} instead "
        "of ResourceNotFound"
    )
    assert message == f"Inference recommendations job {bogus_job_name} for {ctx.account} not found.", f"unexpected DescribeInferenceRecommendationsJob message: {message!r}"

    # Positive control in the same file: the sagemaker client/region wiring itself is healthy --
    # a legitimate, always-available read against the same resource family succeeds normally, so
    # the ResourceNotFound above is a targeted rejection of this one bogus job reference, not a
    # blanket failure to reach the service at all.
    response = sm.list_inference_recommendations_jobs(MaxResults=1)
    assert "InferenceRecommendationsJobs" in response, (
        "ListInferenceRecommendationsJobs response missing "
        f"'InferenceRecommendationsJobs' key entirely: {response!r}"
    )


def _error(fn):
    """The AWS (code, message) raised by fn(); an unexpected SUCCESS raises, so a target that
    accepts what AWS refuses fails loudly rather than reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
