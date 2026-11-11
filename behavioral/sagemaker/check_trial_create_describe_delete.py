"""trial-create-describe-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trial-create-describe-delete"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrial under an existing experiment is describable and DeleteTrial removes it,
    leaving subsequent DescribeTrial and UpdateTrial failing with ResourceNotFound, and the
    freed TrialName reusable."""
    sm = ctx.client("sagemaker")
    experiment_name = ctx.unique_name("sim2real-sm-exp-")
    trial_name = ctx.unique_name("sim2real-sm-trial-")
    tag_spec = [{"Key": "sim2real-check", "Value": CHECK}]

    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_experiment(ExperimentName=experiment_name)))
    sm.create_experiment(ExperimentName=experiment_name, Tags=tag_spec)

    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_trial(TrialName=trial_name)))
    created = sm.create_trial(TrialName=trial_name, ExperimentName=experiment_name, Tags=tag_spec)
    trial_arn = created["TrialArn"]

    desc = sm.describe_trial(TrialName=trial_name)
    assert desc["TrialName"] == trial_name, f"expected TrialName {trial_name!r}, got {desc.get('TrialName')!r}"
    assert desc["ExperimentName"] == experiment_name, (
        f"expected ExperimentName {experiment_name!r}, got {desc.get('ExperimentName')!r}"
    )
    assert desc["TrialArn"] == trial_arn, f"expected TrialArn {trial_arn!r}, got {desc.get('TrialArn')!r}"

    sm.delete_trial(TrialName=trial_name)

    code, message = _error(lambda: sm.describe_trial(TrialName=trial_name))
    assert code == "ResourceNotFound", (
        f"expected DescribeTrial on a deleted trial to raise ResourceNotFound, got {code!r}"
    )
    expected_message = f"Trial '{trial_arn}' does not exist."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    update_code, update_message = _error(lambda: sm.update_trial(TrialName=trial_name, DisplayName="post-delete"))
    assert update_code == "ResourceNotFound", (
        f"expected UpdateTrial on a deleted trial to raise ResourceNotFound, got {update_code!r}"
    )
    assert update_message == expected_message, (
        f"expected message {expected_message!r}, got {update_message!r}"
    )

    recreated = sm.create_trial(TrialName=trial_name, ExperimentName=experiment_name, Tags=tag_spec)
    assert recreated["TrialArn"] == trial_arn, (
        f"expected the freed TrialName {trial_name!r} to be reusable and re-derive the identical "
        f"ARN {trial_arn!r} (SageMaker trial ARNs are deterministic from account+name, not a "
        f"generated id), got {recreated.get('TrialArn')!r}"
    )
    redesc = sm.describe_trial(TrialName=trial_name)
    assert redesc["ExperimentName"] == experiment_name, (
        f"expected recreated trial's ExperimentName {experiment_name!r}, got {redesc.get('ExperimentName')!r}"
    )


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call unexpectedly succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
