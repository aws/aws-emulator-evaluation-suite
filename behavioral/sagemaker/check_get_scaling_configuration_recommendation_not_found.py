"""get-scaling-configuration-recommendation-not-found."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-scaling-configuration-recommendation-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetScalingConfigurationRecommendation for an unknown job and endpoint returns ResourceNotFound with its exact
    message, distinct from the ValidationException (exact message) returned when neither EndpointName nor
    RecommendationId is given.
    """
    sm = ctx.client("sagemaker")

    bogus_job_name = ctx.unique_name("sim2real-behav-irjob-")
    bogus_endpoint_name = ctx.unique_name("sim2real-behav-ep-")

    code, code_message = _error(
        lambda: sm.get_scaling_configuration_recommendation(
            InferenceRecommendationsJobName=bogus_job_name,
            EndpointName=bogus_endpoint_name,
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code}"
    assert code_message == f"Inference recommendations job {bogus_job_name} was not found.", f"unexpected message: {code_message!r}"

    # Distinguishing control: the API discriminates request-shape problems from
    # not-found problems. Omitting BOTH of the mutually-exclusive-but-one-required
    # target fields (EndpointName / RecommendationId) is a different failure mode and
    # must not collapse to the same ResourceNotFound code.
    shape_code, shape_code_message = _error(
        lambda: sm.get_scaling_configuration_recommendation(
            InferenceRecommendationsJobName=bogus_job_name
        )
    )
    assert shape_code == "ValidationException", (
        f"expected ValidationException for missing target field, got {shape_code}"
    )
    assert shape_code_message == (
        "Neither RecommendationId or EndpointName were provided in the input. "
        "Please provide a RecommendationId or EndpointName in the request."
    ), f"unexpected message: {shape_code_message!r}"
    assert shape_code != code, (
        f"missing-target-field rejection ({shape_code!r}) must not collapse into the "
        f"same code as the not-found rejection ({code!r})"
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
