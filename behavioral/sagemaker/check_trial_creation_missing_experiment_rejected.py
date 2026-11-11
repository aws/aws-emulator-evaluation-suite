"""trial-creation-missing-experiment-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trial-creation-missing-experiment-rejected"
GROUP = "e2e"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrial against a non-existent ExperimentName is rejected with ResourceNotFound,
    no orphan trial is left behind, and the same trial name against a real experiment (the
    positive control, in this same file) succeeds normally."""
    sm = ctx.client("sagemaker")

    missing_experiment_name = ctx.unique_name("sim2real-sm-exp-missing-")
    trial_name = ctx.unique_name("sim2real-sm-trial-neg-")

    arn_prefix = f"arn:aws:sagemaker:{ctx.region}:{ctx.account}"

    code, message = _error(
        lambda: sm.create_trial(TrialName=trial_name, ExperimentName=missing_experiment_name)
    )
    assert code == "ResourceNotFound", (
        f"expected ResourceNotFound for CreateTrial against missing experiment "
        f"{missing_experiment_name!r}, got {code!r}"
    )
    expected = f"Experiment '{arn_prefix}:experiment/{missing_experiment_name}' does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: no trial was created under that name.
    describe_code, describe_message = _error(lambda: sm.describe_trial(TrialName=trial_name))
    assert describe_code == "ResourceNotFound", (
        f"trial {trial_name!r} should not exist after the rejected create, got {describe_code!r}"
    )
    expected = f"Trial '{arn_prefix}:experiment-trial/{trial_name}' does not exist."
    assert describe_message == expected, f"expected message {expected!r}, got {describe_message!r}"

    # Positive control: the identical call against a real experiment succeeds.
    experiment_name = ctx.unique_name("sim2real-sm-exp-")
    sm.create_experiment(
        ExperimentName=experiment_name, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: _ignore(lambda: sm.delete_experiment(ExperimentName=experiment_name)))

    created = sm.create_trial(
        TrialName=trial_name,
        ExperimentName=experiment_name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _ignore(lambda: sm.delete_trial(TrialName=trial_name)))

    described = sm.describe_trial(TrialName=trial_name)
    assert described["TrialArn"] == created["TrialArn"], (
        f"expected DescribeTrial ARN to match CreateTrial response, "
        f"got {described['TrialArn']!r} != {created['TrialArn']!r}"
    )
    assert described["ExperimentName"] == experiment_name, (
        f"expected DescribeTrial ExperimentName {experiment_name!r}, got "
        f"{described['ExperimentName']!r}"
    )


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded with {result!r}")


def _ignore(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
