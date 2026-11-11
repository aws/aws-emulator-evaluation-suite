"""search-suggestions-returns-matching-property-names."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "search-suggestions-returns-matching-property-names"
GROUP = "data-plane"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetSearchSuggestions surfaces a just-created trial-component parameter for a matching hint
    but not for an unrelated one, so suggestions reflect indexed account data; the deleted trial
    component then describes as ResourceNotFound."""
    sagemaker = ctx.client("sagemaker")

    suffix = uuid.uuid4().hex[:10]
    custom_param_name = f"Sim2RealCustomHP{suffix}"
    tc_name = ctx.unique_name("sim2real-tc-")

    tc_arn = sagemaker.create_trial_component(
        TrialComponentName=tc_name,
        Parameters={custom_param_name: {"NumberValue": 42.0}},
        Tags=[{"Key": "sim2real", "Value": "search-suggestions-matching-property-names"}],
    )["TrialComponentArn"]
    ctx.on_cleanup(lambda: _best_effort_delete(sagemaker, tc_name))

    # AWS exposes a Parameters entry as "parameters.<key>" (lowercase facet prefix),
    # not the bare key.
    expected_property = f"parameters.{custom_param_name}"

    def _matching_names():
        resp = sagemaker.get_search_suggestions(
            Resource="ExperimentTrialComponent",
            SuggestionQuery={
                "PropertyNameQuery": {"PropertyNameHint": f"Sim2RealCustomHP{suffix}"}
            },
        )
        return [s["PropertyName"] for s in resp.get("PropertyNameSuggestions", [])]

    matching = _poll_until(
        _matching_names,
        lambda names: expected_property in names,
        timeout_s=90.0,
        interval_s=5.0,
    )
    assert expected_property in matching, (
        f"expected {expected_property!r} among suggestions for a matching hint, got {matching!r}"
    )

    # An unrelated hint that shares no prefix with our custom parameter must not surface
    # it -- otherwise the "suggestions" are really just a fixed/global list.
    unrelated_resp = sagemaker.get_search_suggestions(
        Resource="ExperimentTrialComponent",
        SuggestionQuery={"PropertyNameQuery": {"PropertyNameHint": "ZzUnrelatedNoMatch987"}},
    )
    unrelated_names = [s["PropertyName"] for s in unrelated_resp.get("PropertyNameSuggestions", [])]
    assert expected_property not in unrelated_names, (
        f"unrelated hint unexpectedly surfaced {expected_property!r}: {unrelated_names!r}"
    )

    # Deletion is eventually consistent (a describe right after delete can still succeed),
    # so poll rather than asserting on the very next read.
    sagemaker.delete_trial_component(TrialComponentName=tc_name)
    code, message = _poll_until(
        lambda: _error(lambda: sagemaker.describe_trial_component(TrialComponentName=tc_name)),
        lambda e: e[0] == "ResourceNotFound",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert code == "ResourceNotFound", (
        f"expected a deleted trial component to be genuinely gone (ResourceNotFound), got {code!r}"
    )
    expected_message = f"Trial component '{tc_arn}' does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _poll_until(probe, predicate, *, timeout_s=30.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


_SUCCEEDED = "<call succeeded>"


def _error(fn):
    """Call fn(); return its (code, message). A successful call returns (_SUCCEEDED, None),
    a code no AWS error can equal, so a poll keeps waiting and a final assert names it."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _SUCCEEDED, None


def _best_effort_delete(sagemaker, tc_name: str) -> None:
    try:
        sagemaker.delete_trial_component(TrialComponentName=tc_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
