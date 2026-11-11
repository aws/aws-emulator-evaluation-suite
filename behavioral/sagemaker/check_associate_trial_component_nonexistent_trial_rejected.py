"""associate-trial-component-nonexistent-trial-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "associate-trial-component-nonexistent-trial-rejected"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateTrialComponent against a nonexistent TrialName is rejected with ResourceNotFound,
    the component stays unassociated, and a positive control associating it to a real trial in
    the same file still succeeds."""
    sm = ctx.client("sagemaker")
    component_name = ctx.unique_name("sim2real-sm-tc-")
    bogus_trial = ctx.unique_name("sim2real-sm-notrial-")

    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_trial_component(TrialComponentName=component_name)))
    component_arn = sm.create_trial_component(TrialComponentName=component_name)["TrialComponentArn"]
    # The refusal names the trial by ARN; it shares the component's partition/region/account prefix.
    bogus_trial_arn = component_arn.rsplit(":", 1)[0] + f":experiment-trial/{bogus_trial}"

    code, message = _error(
        lambda: sm.associate_trial_component(TrialComponentName=component_name, TrialName=bogus_trial)
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code}"
    expected = f"Trial '{bogus_trial_arn}' does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the failed call didn't conjure the trial into existence, and the
    # component still describes cleanly as a bare, unassociated trial component
    trial_still_missing, missing_message = _error(lambda: sm.describe_trial(TrialName=bogus_trial))
    assert trial_still_missing == "ResourceNotFound", (
        f"expected the bogus trial to still be ResourceNotFound, got {trial_still_missing}"
    )
    expected_missing = f"Trial '{bogus_trial_arn}' does not exist."
    assert missing_message == expected_missing, f"expected message {expected_missing!r}, got {missing_message!r}"
    described_name = sm.describe_trial_component(TrialComponentName=component_name)["TrialComponentName"]
    assert described_name == component_name, f"expected {component_name}, got {described_name}"

    # positive control: associating to a real trial succeeds
    experiment_name = ctx.unique_name("sim2real-sm-exp-")
    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_experiment(ExperimentName=experiment_name)))
    sm.create_experiment(ExperimentName=experiment_name)

    real_trial = ctx.unique_name("sim2real-sm-trial-")
    ctx.on_cleanup(lambda: _safe(lambda: sm.delete_trial(TrialName=real_trial)))
    sm.create_trial(TrialName=real_trial, ExperimentName=experiment_name)

    sm.associate_trial_component(TrialComponentName=component_name, TrialName=real_trial)
    ctx.on_cleanup(
        lambda: _safe(
            lambda: sm.disassociate_trial_component(TrialComponentName=component_name, TrialName=real_trial)
        )
    )
    assert _list_trial_names(sm, real_trial, component_name) is True, (
        f"expected {component_name} to appear in ListTrialComponents for {real_trial}"
    )


def _list_trial_names(sm, trial_name: str, component_name: str) -> bool:
    resp = sm.list_trial_components(TrialName=trial_name)
    names = {c["TrialComponentName"] for c in resp.get("TrialComponentSummaries", [])}
    return component_name in names


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


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
