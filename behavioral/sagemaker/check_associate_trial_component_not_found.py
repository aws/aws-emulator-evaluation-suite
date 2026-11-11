"""associate-trial-component-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-trial-component-not-found"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateTrialComponent with a nonexistent TrialName fails with ResourceNotFound and the exact
    message and the trial still does not exist, while associating the same component with a real
    trial lists it under that trial."""
    sm = ctx.client("sagemaker")

    tc_name = ctx.unique_name("sim2real-behav-tc-")
    tc_arn = sm.create_trial_component(TrialComponentName=tc_name)["TrialComponentArn"]
    ctx.on_cleanup(lambda: sm.delete_trial_component(TrialComponentName=tc_name))

    bogus_trial_name = ctx.unique_name("sim2real-behav-no-such-trial-")
    # The refusal names the trial by ARN; it shares the component's partition/region/account prefix.
    bogus_trial_arn = tc_arn.rsplit(":", 1)[0] + f":experiment-trial/{bogus_trial_name}"
    code, message = _error(
        lambda: sm.associate_trial_component(
            TrialComponentName=tc_name, TrialName=bogus_trial_name
        )
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code}"
    expected = f"Trial '{bogus_trial_arn}' does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect absent: DescribeTrial shows the failed association created no trial (ListTrialComponents
    # also rejects the TrialName), and the component itself still describes.
    still_missing, missing_message = _error(lambda: sm.describe_trial(TrialName=bogus_trial_name))
    assert still_missing == "ResourceNotFound", (
        f"expected the bogus trial to still not exist, got {still_missing}"
    )
    expected_missing = f"Trial '{bogus_trial_arn}' does not exist."
    assert missing_message == expected_missing, f"expected message {expected_missing!r}, got {missing_message!r}"
    tc_desc = sm.describe_trial_component(TrialComponentName=tc_name)
    assert tc_desc["TrialComponentName"] == tc_name, tc_desc

    # Set up a real Trial for the positive control.
    exp_name = ctx.unique_name("sim2real-behav-exp-")
    sm.create_experiment(ExperimentName=exp_name)
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=exp_name))

    trial_name = ctx.unique_name("sim2real-behav-trial-")
    sm.create_trial(TrialName=trial_name, ExperimentName=exp_name)
    ctx.on_cleanup(lambda: sm.delete_trial(TrialName=trial_name))

    # Positive control: associating with a real Trial succeeds.
    sm.associate_trial_component(TrialComponentName=tc_name, TrialName=trial_name)
    ctx.on_cleanup(
        lambda: sm.disassociate_trial_component(
            TrialComponentName=tc_name, TrialName=trial_name
        )
    )

    after = sm.list_trial_components(TrialName=trial_name)["TrialComponentSummaries"]
    assert any(c["TrialComponentName"] == tc_name for c in after), after


def _error(fn):
    """Return (code, message) of the call's ClientError; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
