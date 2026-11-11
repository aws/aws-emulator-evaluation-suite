"""trial-delete-with-attached-component-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "trial-delete-with-attached-component-rejected"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


def _error(fn):
    """Return (code, message) of the service error; a call that succeeds fails the check."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        err = getattr(exc, "response", {}).get("Error", {})
        if err.get("Code") is None:
            raise
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteTrial is rejected while a TrialComponent is still associated to it; the Trial
    remains intact until the component is disassociated/deleted, at which point delete succeeds
    (positive control in this same file)."""
    sm = ctx.client("sagemaker")

    experiment_name = ctx.unique_name("sim2real-behav-exp-")
    trial_name = ctx.unique_name("sim2real-behav-trial-")
    component_name = ctx.unique_name("sim2real-behav-tc-")

    sm.create_experiment(
        ExperimentName=experiment_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=experiment_name))

    sm.create_trial(
        TrialName=trial_name,
        ExperimentName=experiment_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    trial_deleted = False

    def _cleanup_trial():
        if not trial_deleted:
            sm.delete_trial(TrialName=trial_name)

    ctx.on_cleanup(_cleanup_trial)

    sm.create_trial_component(
        TrialComponentName=component_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: sm.delete_trial_component(TrialComponentName=component_name))

    sm.associate_trial_component(TrialComponentName=component_name, TrialName=trial_name)

    trial_arn = f"arn:aws:sagemaker:{ctx.region}:{ctx.account}:experiment-trial/{trial_name}"
    not_found = f"Trial '{trial_arn}' does not exist."

    # Break exactly one thing: try to delete a trial that still has an associated component.
    code, message = _error(lambda: sm.delete_trial(TrialName=trial_name))
    assert code == "ValidationException", (
        f"expected DeleteTrial on a trial with an associated component to fail with "
        f"ValidationException; got {code!r}"
    )
    expected = f"Trial '{trial_arn}' has trial components and cannot be deleted."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: the trial is still there, unharmed.
    described = sm.describe_trial(TrialName=trial_name)
    assert described["TrialName"] == trial_name, (
        f"expected the trial to survive the rejected delete; DescribeTrial returned "
        f"{described.get('TrialName')!r}"
    )

    # Positive control: once the component is disassociated and removed, deletion succeeds.
    sm.disassociate_trial_component(TrialComponentName=component_name, TrialName=trial_name)
    sm.delete_trial(TrialName=trial_name)
    trial_deleted = True

    code_after, message_after = _error(lambda: sm.describe_trial(TrialName=trial_name))
    assert code_after == "ResourceNotFound", (
        f"expected DescribeTrial on the deleted trial to 404 with ResourceNotFound; got "
        f"{code_after!r}"
    )
    assert message_after == not_found, f"expected message {not_found!r}, got {message_after!r}"

    # Deletes prove gone AND unusable: a mutation on the now-dead trial id must also fail.
    code_mutation, message_mutation = _error(lambda: sm.delete_trial(TrialName=trial_name))
    assert code_mutation == "ResourceNotFound", (
        f"expected a second DeleteTrial against the already-deleted trial id to fail with "
        f"ResourceNotFound; got {code_mutation!r}"
    )
    assert message_mutation == not_found, (
        f"expected message {not_found!r}, got {message_mutation!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
