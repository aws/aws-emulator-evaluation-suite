"""e2e-trial-component-association-nonexistent-trial-rejected."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-trial-component-association-nonexistent-trial-rejected"
GROUP = "e2e"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateTrialComponent naming a nonexistent trial is refused with ResourceNotFound and its exact message,
    ListTrialComponents for that trial is refused the same way, and the component's earlier real association is
    unchanged.
    """
    sm = ctx.client("sagemaker")

    experiment_name = ctx.unique_name("sim2real-sm-exp-")
    sm.create_experiment(ExperimentName=experiment_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=experiment_name))

    trial_name = ctx.unique_name("sim2real-sm-trial-")
    sm.create_trial(
        TrialName=trial_name,
        ExperimentName=experiment_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_trial(TrialName=trial_name))

    component_name = ctx.unique_name("sim2real-sm-tc-")
    sm.create_trial_component(
        TrialComponentName=component_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_trial_component(TrialComponentName=component_name))

    # Positive control: a real association against the real trial succeeds.
    assoc = sm.associate_trial_component(TrialComponentName=component_name, TrialName=trial_name)
    ctx.on_cleanup(
        lambda: sm.disassociate_trial_component(TrialComponentName=component_name, TrialName=trial_name)
    )
    summaries = _poll_until(
        lambda: sm.list_trial_components(TrialName=trial_name)["TrialComponentSummaries"],
        lambda s: any(c["TrialComponentName"] == component_name for c in s),
        timeout_s=30,
        interval_s=2,
    )
    assert len(summaries) == 1

    # Break exactly one thing: a syntactically valid but nonexistent trial name.
    bogus_trial_name = ctx.unique_name("sim2real-sm-notrial-")
    code, message = _error(
        lambda: sm.associate_trial_component(TrialComponentName=component_name, TrialName=bogus_trial_name)
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code}"
    bogus_trial_arn = f"arn:aws:sagemaker:{ctx.region}:{ctx.account}:experiment-trial/{bogus_trial_name}"
    expected_message = f"Trial '{bogus_trial_arn}' does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: ListTrialComponents(TrialName=<nonexistent>)
    # does NOT degrade to an empty filter result -- it raises the identical ResourceNotFound,
    # rejecting the lookup outright rather than silently reporting zero components.
    leftover_code, leftover_message = _error(lambda: sm.list_trial_components(TrialName=bogus_trial_name))
    assert leftover_code == "ResourceNotFound", f"expected ResourceNotFound, got {leftover_code}"
    assert leftover_message == expected_message, (
        f"expected message {expected_message!r}, got {leftover_message!r}"
    )

    # Positive control still holds: the real association is untouched.
    summaries_after = sm.list_trial_components(TrialName=trial_name)["TrialComponentSummaries"]
    assert len(summaries_after) == 1
    assert summaries_after[0]["TrialComponentArn"] == assoc["TrialComponentArn"]


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _error(fn: Callable[[], Any]) -> tuple[str, str | None]:
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
