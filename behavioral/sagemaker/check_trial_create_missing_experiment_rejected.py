"""trial-create-missing-experiment-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trial-create-missing-experiment-rejected"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrial referencing a non-existent ExperimentName is rejected, no trial is
    persisted under that name, and creating the same trial against a real, existing
    experiment (positive control) still succeeds in the same run.
    """
    sm = ctx.client("sagemaker")
    experiment_name = ctx.unique_name("sim2real-experiment-")
    trial_name = ctx.unique_name("sim2real-trial-")
    bogus_experiment_name = ctx.unique_name("sim2real-no-such-experiment-")

    arn_prefix = f"arn:aws:sagemaker:{ctx.region}:{ctx.account}"

    code, message = _error(
        lambda: sm.create_trial(TrialName=trial_name, ExperimentName=bogus_experiment_name)
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    expected = f"Experiment '{arn_prefix}:experiment/{bogus_experiment_name}' does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: no trial was persisted under that name
    describe_code, describe_message = _error(lambda: sm.describe_trial(TrialName=trial_name))
    assert describe_code == "ResourceNotFound", (
        f"trial {trial_name!r} should not exist after the rejected create, "
        f"got describe code {describe_code!r}"
    )
    expected = f"Trial '{arn_prefix}:experiment-trial/{trial_name}' does not exist."
    assert describe_message == expected, f"expected message {expected!r}, got {describe_message!r}"

    # positive control: the same trial name against a real experiment succeeds
    sm.create_experiment(ExperimentName=experiment_name)
    ctx.on_cleanup(lambda: _delete_experiment_ignore(sm, experiment_name))

    sm.create_trial(TrialName=trial_name, ExperimentName=experiment_name)
    ctx.on_cleanup(lambda: _delete_trial_ignore(sm, trial_name))

    desc = sm.describe_trial(TrialName=trial_name)
    assert desc["TrialName"] == trial_name, (
        f"expected TrialName {trial_name!r}, got {desc.get('TrialName')!r}"
    )
    assert desc["ExperimentName"] == experiment_name, (
        f"expected ExperimentName {experiment_name!r}, got {desc.get('ExperimentName')!r}"
    )


def _error(fn):
    """Return (code, message) of the ClientError; a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _delete_trial_ignore(sm, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.delete_trial(TrialName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _delete_experiment_ignore(sm, name: str) -> None:
    from botocore.exceptions import ClientError

    try:
        sm.delete_experiment(ExperimentName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
