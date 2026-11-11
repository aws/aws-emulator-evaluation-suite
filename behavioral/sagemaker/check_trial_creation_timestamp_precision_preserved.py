"""trial-creation-timestamp-precision-preserved."""
from __future__ import annotations

import time
from datetime import datetime

from behavioral_harness import tags

CHECK = "trial-creation-timestamp-precision-preserved"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A trial's CreationTime keeps sub-second precision, and repeated DescribeTrial calls return
    exactly the same value, never a re-rounded or regenerated timestamp.
    """
    sm = ctx.client("sagemaker")

    experiment_name = ctx.unique_name("sim2real-trialexp-")
    sm.create_experiment(
        ExperimentName=experiment_name,
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=experiment_name))

    trial_name = ctx.unique_name("sim2real-trial-")
    sm.create_trial(
        TrialName=trial_name,
        ExperimentName=experiment_name,
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_trial(TrialName=trial_name))

    first = sm.describe_trial(TrialName=trial_name)
    first_creation_time = first["CreationTime"]

    # The value must be a real precision-bearing timestamp type (checked with
    # isinstance, not hasattr -- every datetime instance has a microsecond
    # attribute regardless of its value, so hasattr can never fail here).
    assert isinstance(first_creation_time, datetime), (
        f"CreationTime is not a precision-bearing timestamp type: {type(first_creation_time)!r}"
    )

    # Repeatedly re-read the trial over a bounded window (rather than a single
    # fixed sleep-then-check): each poll re-asserts the observed invariant, so a
    # backend that regenerates/rounds CreationTime on a later read fails fast at
    # the poll that first observes the drift, rather than only after a blind delay.
    _poll_creation_time_stable(sm, trial_name, first_creation_time, timeout_s=3.0, interval_s=0.5)

    # Positive control: a second, distinct trial created afterwards must carry
    # its own CreationTime that is monotonically non-decreasing relative to the
    # first trial's -- proving CreationTime tracks real creation order rather
    # than being a constant or a value tied to the read call.
    trial_name_2 = ctx.unique_name("sim2real-trial-")
    sm.create_trial(
        TrialName=trial_name_2,
        ExperimentName=experiment_name,
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: sm.delete_trial(TrialName=trial_name_2))
    third = sm.describe_trial(TrialName=trial_name_2)
    assert third["CreationTime"] >= first_creation_time, (
        f"second trial's CreationTime {third['CreationTime']!r} precedes the first "
        f"trial's {first_creation_time!r} despite being created later"
    )

    # Sub-second precision: a millisecond stamp lands on a whole second about once in a
    # thousand creations, so of two independent creations at least one carries a nonzero
    # sub-second component unless the target rounds to whole seconds.
    assert first_creation_time.microsecond != 0 or third["CreationTime"].microsecond != 0, (
        "both trials' CreationTime have zero microseconds -- looks rounded to whole-second "
        f"precision rather than carrying genuine sub-second resolution: "
        f"{first_creation_time!r}, {third['CreationTime']!r}"
    )


def _poll_creation_time_stable(sm, trial_name, expected, *, timeout_s: float, interval_s: float):
    """Poll DescribeTrial repeatedly over a bounded window, asserting on each
    poll that CreationTime still equals `expected` -- fails fast on the first
    drifting read rather than sleeping blind then checking once at the end."""
    deadline = time.monotonic() + timeout_s
    polls = 0
    while time.monotonic() < deadline:
        time.sleep(interval_s)
        polls += 1
        got = sm.describe_trial(TrialName=trial_name)["CreationTime"]
        assert got == expected, (
            "CreationTime drifted across repeated DescribeTrial polls on the same "
            f"trial after {polls} poll(s): {expected!r} != {got!r}"
        )
    assert polls > 0, "poll loop never executed -- timeout_s/interval_s misconfigured"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

