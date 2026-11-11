"""trial-create-describe-delete-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "trial-create-describe-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrial under an experiment is describable; DeleteTrial removes it (and the id is
    reusable and no longer mutable), while the experiment stays intact."""
    sm = ctx.client("sagemaker")

    experiment_name = ctx.unique_name("sim2real-sm-exp-")
    sm.create_experiment(ExperimentName=experiment_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_experiment_if_present(ctx, experiment_name))

    trial_name = ctx.unique_name("sim2real-sm-trial-")
    created = sm.create_trial(
        TrialName=trial_name,
        ExperimentName=experiment_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    trial_arn = created["TrialArn"]

    described = sm.describe_trial(TrialName=trial_name)
    assert described["TrialName"] == trial_name, f"expected TrialName={trial_name!r}, got {described['TrialName']!r}"
    assert described["TrialArn"] == trial_arn, f"expected TrialArn={trial_arn!r}, got {described['TrialArn']!r}"
    assert described["ExperimentName"] == experiment_name, (
        f"expected ExperimentName={experiment_name!r}, got {described['ExperimentName']!r}"
    )

    sm.delete_trial(TrialName=trial_name)

    code, message = _error(lambda: sm.describe_trial(TrialName=trial_name))
    assert code == "ResourceNotFound", f"expected DescribeTrial on a deleted trial to raise ResourceNotFound, got {code!r}"
    expected_message = f"Trial '{trial_arn}' does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # A mutation on the dead id must also fail, not just a read.
    update_code, update_message = _error(lambda: sm.update_trial(TrialName=trial_name, DisplayName="ghost"))
    assert update_code == "ResourceNotFound", (
        f"expected UpdateTrial on a deleted trial to raise ResourceNotFound, got {update_code!r}"
    )
    assert update_message == expected_message, (
        f"expected message {expected_message!r}, got {update_message!r}"
    )

    # The trial name is reusable once the original is gone.
    recreated = sm.create_trial(
        TrialName=trial_name,
        ExperimentName=experiment_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_trial_if_present(ctx, trial_name))
    redescribed = sm.describe_trial(TrialName=trial_name)
    assert redescribed["TrialArn"] == recreated["TrialArn"], (
        f"expected the reused name to describe the new trial's own arn {recreated['TrialArn']!r}, "
        f"got {redescribed['TrialArn']!r}"
    )

    # The experiment itself must survive the trial's deletion.
    still_there = sm.describe_experiment(ExperimentName=experiment_name)
    assert still_there["ExperimentName"] == experiment_name, (
        f"expected the parent experiment {experiment_name!r} to survive trial deletion, "
        f"got {still_there['ExperimentName']!r}"
    )


def _delete_experiment_if_present(ctx, experiment_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_experiment(ExperimentName=experiment_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _delete_trial_if_present(ctx, trial_name: str) -> None:
    sm = ctx.client("sagemaker")
    try:
        sm.delete_trial(TrialName=trial_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
