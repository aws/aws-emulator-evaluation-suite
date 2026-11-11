"""trial-component-association-lifecycle."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trial-component-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A trial component associated to a trial appears in the trial's component list;
    disassociating removes it from that list, and the (now-empty) trial can then be
    deleted so a later describe 404s."""
    sm = ctx.client("sagemaker")
    exp_name = ctx.unique_name("sim2real-behav-exp-")
    trial_name = ctx.unique_name("sim2real-behav-trial-")
    tc_name = ctx.unique_name("sim2real-behav-tc-")

    tags = [{"Key": "sim2real", "Value": CHECK}]

    sm.create_experiment(ExperimentName=exp_name, Tags=tags)
    ctx.on_cleanup(lambda: _delete_experiment_best_effort(sm, exp_name))

    trial_arn = sm.create_trial(TrialName=trial_name, ExperimentName=exp_name, Tags=tags)["TrialArn"]
    ctx.on_cleanup(lambda: _delete_trial_best_effort(sm, trial_name))

    sm.create_trial_component(TrialComponentName=tc_name, Tags=tags)
    ctx.on_cleanup(lambda: _delete_trial_component_best_effort(sm, tc_name))

    sm.associate_trial_component(TrialComponentName=tc_name, TrialName=trial_name)

    before = sm.list_trial_components(TrialName=trial_name)["TrialComponentSummaries"]
    assert any(tc["TrialComponentName"] == tc_name for tc in before), (
        "associated trial component did not appear in the trial's component list"
    )

    sm.disassociate_trial_component(TrialComponentName=tc_name, TrialName=trial_name)

    after = sm.list_trial_components(TrialName=trial_name)["TrialComponentSummaries"]
    assert not any(tc["TrialComponentName"] == tc_name for tc in after), (
        "disassociated trial component still appears in the trial's component list"
    )

    sm.delete_trial(TrialName=trial_name)

    code, message = _error(lambda: sm.describe_trial(TrialName=trial_name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code}"
    expected_message = f"Trial '{trial_arn}' does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_experiment_best_effort(sm, name):
    try:
        sm.delete_experiment(ExperimentName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _delete_trial_best_effort(sm, name):
    try:
        sm.delete_trial(TrialName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _delete_trial_component_best_effort(sm, name):
    try:
        sm.delete_trial_component(TrialComponentName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
