"""trial-and-trial-component-association-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "trial-and-trial-component-association-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A trial component association is visible via ListTrialComponents and the trial
    survives while associated; deleting requires disassociating first, then DescribeTrial
    404s once the trial itself is deleted."""
    sm = ctx.client("sagemaker")
    experiment_name = ctx.unique_name("sim2real-exp-")
    trial_name = ctx.unique_name("sim2real-trial-")
    component_name = ctx.unique_name("sim2real-tc-")

    sm.create_experiment(ExperimentName=experiment_name)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_experiment(ExperimentName=experiment_name)))

    trial_arn = sm.create_trial(TrialName=trial_name, ExperimentName=experiment_name)["TrialArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_trial(TrialName=trial_name)))

    component_arn = sm.create_trial_component(TrialComponentName=component_name)["TrialComponentArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_trial_component(TrialComponentName=component_name)))

    assoc = sm.associate_trial_component(TrialComponentName=component_name, TrialName=trial_name)
    assert assoc["TrialArn"] == trial_arn, (
        f"expected AssociateTrialComponent response TrialArn {trial_arn!r}, got {assoc.get('TrialArn')!r}"
    )

    # The association must be visible through ListTrialComponents while the trial
    # itself remains fully intact and describable.
    listed = sm.list_trial_components(TrialName=trial_name)["TrialComponentSummaries"]
    assert any(tc["TrialComponentName"] == component_name for tc in listed), (
        "associated trial component not reflected in ListTrialComponents(TrialName=...)"
    )
    described_trial = sm.describe_trial(TrialName=trial_name)
    assert described_trial["TrialArn"] == trial_arn, (
        f"expected DescribeTrial TrialArn {trial_arn!r}, got {described_trial.get('TrialArn')!r}"
    )
    assert described_trial["ExperimentName"] == experiment_name, (
        f"expected DescribeTrial ExperimentName {experiment_name!r}, got {described_trial.get('ExperimentName')!r}"
    )

    # A trial cannot be deleted while it still has associated components: disassociate
    # and delete the component first, in that order, before deleting the trial.
    sm.disassociate_trial_component(TrialComponentName=component_name, TrialName=trial_name)
    listed_after = sm.list_trial_components(TrialName=trial_name)["TrialComponentSummaries"]
    assert not any(tc["TrialComponentName"] == component_name for tc in listed_after), (
        "trial component still associated after DisassociateTrialComponent"
    )

    sm.delete_trial_component(TrialComponentName=component_name)
    tc_code, tc_message = _poll_until(
        lambda: _error(lambda: sm.describe_trial_component(TrialComponentName=component_name)),
        lambda e: e[0] != _SUCCEEDED,
        timeout_s=60,
        interval_s=3,
    )
    assert tc_code == "ResourceNotFound", f"expected ResourceNotFound after delete_trial_component, got {tc_code}"
    expected_tc = f"Trial component '{component_arn}' does not exist."
    assert tc_message == expected_tc, f"expected message {expected_tc!r}, got {tc_message!r}"

    sm.delete_trial(TrialName=trial_name)

    code, message = _poll_until(
        lambda: _error(lambda: sm.describe_trial(TrialName=trial_name)),
        lambda e: e[0] != _SUCCEEDED,
        timeout_s=60,
        interval_s=3,
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code}"
    expected_trial = f"Trial '{trial_arn}' does not exist."
    assert message == expected_trial, f"expected message {expected_trial!r}, got {message!r}"


_SUCCEEDED = "<call succeeded>"


def _error(fn):
    """Call fn(); return its (code, message). A successful call returns (_SUCCEEDED, None),
    a code no AWS error can equal, so a poll keeps waiting and a final assert names it."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return _SUCCEEDED, None


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            return value
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
