"""get-scaling-configuration-recommendation-unknown-endpoint-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-scaling-configuration-recommendation-unknown-endpoint-not-found"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetScalingConfigurationRecommendation for a job and endpoint that do not exist returns ResourceNotFound with its
    exact message, DescribeInferenceRecommendationsJob shows no job was registered under that name, and
    ListInferenceRecommendationsJobs succeeds on the same client.
    """
    sm = ctx.client("sagemaker")
    fake_job_name = ctx.unique_name("sim2real-noexist-job-")
    fake_endpoint_name = ctx.unique_name("sim2real-noexist-ep-")

    code, code_message = _error(
        lambda: sm.get_scaling_configuration_recommendation(
            InferenceRecommendationsJobName=fake_job_name,
            EndpointName=fake_endpoint_name,
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code}"
    assert code_message == f"Inference recommendations job {fake_job_name} was not found.", f"unexpected message: {code_message!r}"

    # Effect-absent: the rejected call must not have implicitly registered a job under
    # that name as a side effect of the lookup.
    describe_code, describe_code_message = _error(
        lambda: sm.describe_inference_recommendations_job(JobName=fake_job_name)
    )
    assert describe_code == "ResourceNotFound", (
        "GetScalingConfigurationRecommendation appears to have created a job as a "
        f"side effect of a rejected request; DescribeInferenceRecommendationsJob "
        f"returned {describe_code!r} instead of ResourceNotFound"
    )
    assert describe_code_message == f"Inference recommendations job {fake_job_name} for {ctx.account} not found.", f"unexpected message: {describe_code_message!r}"

    # Positive control: the sagemaker client/region wiring itself is healthy -- a
    # legitimate, always-available read against the same resource family succeeds
    # normally, so the ResourceNotFound above is a targeted rejection of this one
    # bogus job/endpoint pair, not a blanket failure to reach the service at all.
    response = sm.list_inference_recommendations_jobs(MaxResults=1)
    assert "InferenceRecommendationsJobs" in response, (
        "positive control failed: list_inference_recommendations_jobs did not return "
        "the expected shape, so the ResourceNotFound above cannot be trusted as a "
        "targeted rejection"
    )


def _error(fn):
    """The AWS (code, message) raised by fn(); an unexpected SUCCESS raises, so a target that
    accepts what AWS refuses fails loudly rather than reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
