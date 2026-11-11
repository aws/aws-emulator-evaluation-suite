"""get-scaling-configuration-recommendation-not-found-for-missing-endpoint."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-scaling-configuration-recommendation-not-found-for-missing-endpoint"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetScalingConfigurationRecommendation against a non-existent inference recommendations
    job / endpoint pairing returns ResourceNotFound rather than an empty recommendation.
    """
    sm = ctx.client("sagemaker")
    missing_job_name = ctx.unique_name("sim2real-nonexistent-irjob-")
    missing_endpoint_name = ctx.unique_name("sim2real-nonexistent-ep-")

    code, code_message = _error(
        lambda: sm.get_scaling_configuration_recommendation(
            InferenceRecommendationsJobName=missing_job_name,
            EndpointName=missing_endpoint_name,
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    assert code_message == f"Inference recommendations job {missing_job_name} was not found.", f"unexpected message: {code_message!r}"

    # Effect-absent: the rejected lookup must not have implicitly registered a job under
    # that name as a side effect.
    describe_code, describe_code_message = _error(
        lambda: sm.describe_inference_recommendations_job(JobName=missing_job_name)
    )
    assert describe_code == "ResourceNotFound", (
        "GetScalingConfigurationRecommendation appears to have created a job as a side "
        f"effect of the rejected request; DescribeInferenceRecommendationsJob returned "
        f"{describe_code!r} instead of ResourceNotFound"
    )
    assert describe_code_message == f"Inference recommendations job {missing_job_name} for {ctx.account} not found.", f"unexpected message: {describe_code_message!r}"

    # Positive control: a legitimate, always-available read against the same resource
    # family succeeds normally, so the ResourceNotFound above is a targeted rejection of
    # this one bogus reference rather than a blanket inability to reach the operation, or
    # an operation that rejects every input it is given.
    listing = sm.list_inference_recommendations_jobs(MaxResults=1)
    assert "InferenceRecommendationsJobs" in listing, (
        f"expected a well-formed ListInferenceRecommendationsJobs response, got {listing!r}"
    )


def _error(fn):
    """The AWS (code, message) raised by fn(); an unexpected SUCCESS raises, so a target that
    accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
