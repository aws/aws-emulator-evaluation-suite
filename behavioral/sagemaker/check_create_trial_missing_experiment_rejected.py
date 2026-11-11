"""create-trial-missing-experiment-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-trial-missing-experiment-rejected"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrial naming a nonexistent experiment is refused with ResourceNotFound and its exact
    message and creates no trial (DescribeTrial: ResourceNotFound); once the experiment exists, the
    identical CreateTrial succeeds and the trial describes under that experiment.
    """
    sm = ctx.client("sagemaker")
    bogus_experiment = ctx.unique_name("sim2real-sm-noexp-")
    trial_name = ctx.unique_name("sim2real-sm-trial-")

    code, message = _error(
        lambda: sm.create_trial(TrialName=trial_name, ExperimentName=bogus_experiment)
    )
    assert code == "ResourceNotFound", (
        f"expected ResourceNotFound creating a trial against a nonexistent experiment, got {code!r}"
    )
    expected = (
        f"Experiment 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:experiment/{bogus_experiment}' "
        "does not exist."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # effect absent: the trial was never created against the nonexistent experiment
    describe_code, describe_message = _error(lambda: sm.describe_trial(TrialName=trial_name))
    assert describe_code == "ResourceNotFound", (
        f"expected trial {trial_name!r} to be absent after the rejected create, "
        f"got describe code {describe_code!r}"
    )
    expected_absent = (
        f"Trial 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:experiment-trial/{trial_name}' "
        "does not exist."
    )
    assert describe_message == expected_absent, (
        f"expected {expected_absent!r}, got {describe_message!r}"
    )

    # restore: back the same experiment name with a real experiment, then retry the identical
    # CreateTrial call (same TrialName, same ExperimentName) and confirm it succeeds.
    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_experiment(ExperimentName=bogus_experiment)))
    sm.create_experiment(
        ExperimentName=bogus_experiment,
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )

    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_trial(TrialName=trial_name)))
    sm.create_trial(
        TrialName=trial_name,
        ExperimentName=bogus_experiment,
        Tags=[{"Key": "sim2real-behav-check", "Value": CHECK}],
    )

    desc = sm.describe_trial(TrialName=trial_name)
    assert desc["ExperimentName"] == bogus_experiment, (
        f"expected the restored trial's ExperimentName to be {bogus_experiment!r}, "
        f"got {desc.get('ExperimentName')!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
