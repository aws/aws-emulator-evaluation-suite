"""get-search-suggestions-matches-created-resource."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "get-search-suggestions-matches-created-resource"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """After a tagged Experiment is created, GetSearchSuggestions for the Experiment resource suggests a
    property naming its tag key, and the same call with an unknown resource type is refused with
    ValidationException and its exact message.
    """
    sm = ctx.client("sagemaker")
    experiment_name = ctx.unique_name("sim2real-exp-")
    tag_key = ctx.unique_name("Sim2RealSuggest-").replace("-", "")

    sm.create_experiment(
        ExperimentName=experiment_name,
        DisplayName=experiment_name,
        Tags=[{"Key": tag_key, "Value": "search-suggestion-probe"}],
    )
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=experiment_name))

    hint = tag_key[:-4]  # a distinctive prefix of the tag key, unlikely to collide
    names = _poll_until(
        lambda: [
            s["PropertyName"]
            for s in sm.get_search_suggestions(
                Resource="Experiment",
                SuggestionQuery={"PropertyNameQuery": {"PropertyNameHint": hint}},
            )["PropertyNameSuggestions"]
        ],
        lambda names: any(tag_key in n for n in names),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert any(tag_key in n for n in names), (
        f"expected a suggestion naming Tags.{tag_key} after tagging a new Experiment, got {names}"
    )

    code, code_message = _error(
        lambda: sm.get_search_suggestions(
            Resource="sim2real-not-a-real-resource-type",
            SuggestionQuery={"PropertyNameQuery": {"PropertyNameHint": "x"}},
        )
    )
    assert code == "ValidationException", f"expected ValidationException for a bogus Resource, got {code!r}"
    assert code_message == (
        "1 validation error detected: Value 'sim2real-not-a-real-resource-type' at 'resource' "
        "failed to satisfy constraint: Member must satisfy enum value set: [App, Pipeline, "
        "ModelPackageGroup, TrainingJob, InferenceComponent, HubContent, Domain, "
        "ExperimentTrialComponent, FeatureMetadata, FeatureGroup, Model, HyperParameterTuningJob, "
        "Endpoint, PipelineVersion, PipelineExecution, EndpointConfig, ModelCard, Project, "
        "ExperimentTrial, Image, Job, ImageVersion, ModelPackage, Experiment, UserProfile]"
    ), f"unexpected message: {code_message!r}"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


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
