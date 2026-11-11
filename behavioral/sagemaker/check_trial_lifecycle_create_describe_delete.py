"""trial-lifecycle-create-describe-delete."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trial-lifecycle-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Trial transitions from created to describable to 404 after delete."""
    sm = ctx.client("sagemaker")
    experiment_name = ctx.unique_name("sim2real-experiment-")
    trial_name = ctx.unique_name("sim2real-trial-")

    sm.create_experiment(ExperimentName=experiment_name, DisplayName="sim2real-behavioral-experiment")
    ctx.on_cleanup(lambda: _delete_experiment_ignore(sm, experiment_name))

    created = sm.create_trial(TrialName=trial_name, ExperimentName=experiment_name)
    arn = created["TrialArn"]
    ctx.on_cleanup(lambda: _delete_trial_ignore(sm, trial_name))

    desc = sm.describe_trial(TrialName=trial_name)
    assert desc["TrialArn"] == arn, f"expected TrialArn {arn!r}, got {desc['TrialArn']!r}"
    assert desc["TrialName"] == trial_name, f"expected TrialName {trial_name!r}, got {desc['TrialName']!r}"
    assert desc["ExperimentName"] == experiment_name, (
        f"expected ExperimentName {experiment_name!r}, got {desc['ExperimentName']!r}"
    )

    sm.delete_trial(TrialName=trial_name)

    code, message = _error(lambda: sm.describe_trial(TrialName=trial_name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code!r}"
    expected = (
        f"Trial 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:experiment-trial/{trial_name}' "
        "does not exist."
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    still_there = sm.describe_experiment(ExperimentName=experiment_name)
    assert still_there["ExperimentName"] == experiment_name, (
        f"deleting the trial must not remove its experiment, got {still_there['ExperimentName']!r}"
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
