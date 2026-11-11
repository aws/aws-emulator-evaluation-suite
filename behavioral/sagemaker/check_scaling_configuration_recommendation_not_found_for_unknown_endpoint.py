"""scaling-configuration-recommendation-not-found-for-unknown-endpoint."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "scaling-configuration-recommendation-not-found-for-unknown-endpoint"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetScalingConfigurationRecommendation for a job and endpoint never created returns
    ResourceNotFound with its exact message, DescribeInferenceRecommendationsJob shows no job exists
    under that name, and ListInferenceRecommendationsJobs succeeds.
    """
    sagemaker = ctx.client("sagemaker")

    bogus_job_name = ctx.unique_name("sim2real-irj-")[:64]
    bogus_endpoint_name = ctx.unique_name("sim2real-ep-")[:63]

    code, message = _error(
        lambda: sagemaker.get_scaling_configuration_recommendation(
            InferenceRecommendationsJobName=bogus_job_name,
            EndpointName=bogus_endpoint_name,
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    expected_message = f"Inference recommendations job {bogus_job_name} was not found."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect-absent: the rejected call must not have implicitly registered a job under
    # that name as a side effect of the lookup.
    describe_code, describe_message = _error(
        lambda: sagemaker.describe_inference_recommendations_job(JobName=bogus_job_name)
    )
    assert describe_code == "ResourceNotFound", (
        "GetScalingConfigurationRecommendation appears to have created a job as a "
        f"side effect of the rejected request; DescribeInferenceRecommendationsJob "
        f"returned {describe_code!r} instead of ResourceNotFound"
    )
    expected_describe = f"Inference recommendations job {bogus_job_name} for {ctx.account} not found."
    assert describe_message == expected_describe, (
        f"expected message {expected_describe!r}, got {describe_message!r}"
    )

    # Positive control: a legitimate, always-available read against the same resource
    # family succeeds normally, so the ResourceNotFound above is a targeted rejection of
    # this one bogus reference rather than the account/region being unable to reach the
    # operation at all.
    listing = sagemaker.list_inference_recommendations_jobs(MaxResults=1)
    assert "InferenceRecommendationsJobs" in listing, (
        f"expected a well-formed ListInferenceRecommendationsJobs response, got {listing!r}"
    )


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises, because
    an emulator ACCEPTING a lookup real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
