"""get-scaling-configuration-recommendation-endpoint-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-scaling-configuration-recommendation-endpoint-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetScalingConfigurationRecommendation naming a job that does not exist returns ResourceNotFound with its exact
    message, DescribeInferenceRecommendationsJob shows that no job was registered under that name, and
    ListInferenceRecommendationsJobs succeeds on the same client.
    """
    sm = ctx.client("sagemaker")

    bogus_job_name = ctx.unique_name("sim2real-irjob-")
    bogus_endpoint_name = ctx.unique_name("sim2real-irendpoint-")

    code, code_message = _error(
        lambda: sm.get_scaling_configuration_recommendation(
            InferenceRecommendationsJobName=bogus_job_name,
            EndpointName=bogus_endpoint_name,
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    assert code_message == f"Inference recommendations job {bogus_job_name} was not found.", f"unexpected message: {code_message!r}"

    side_effect_code, side_effect_code_message = _error(
        lambda: sm.describe_inference_recommendations_job(JobName=bogus_job_name)
    )
    assert side_effect_code == "ResourceNotFound", (
        "GetScalingConfigurationRecommendation appears to have registered a job as a "
        f"side effect of a rejected request; DescribeInferenceRecommendationsJob "
        f"returned {side_effect_code!r} instead of ResourceNotFound"
    )
    assert side_effect_code_message == f"Inference recommendations job {bogus_job_name} for {ctx.account} not found.", f"unexpected message: {side_effect_code_message!r}"

    response = sm.list_inference_recommendations_jobs(MaxResults=1)
    assert "InferenceRecommendationsJobs" in response, (
        "positive control failed: a plain list call against the same sagemaker "
        f"wiring did not return the expected shape: {response!r}"
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
