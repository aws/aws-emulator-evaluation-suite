"""experiment-trial-component-association-flow."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "experiment-trial-component-association-flow"
GROUP = "e2e"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A standalone trial component lists under no trial, then under the trial after
    AssociateTrialComponent (which returns both ARNs) while DescribeTrial keeps its experiment; after
    cleanup the component, trial and experiment each answer ResourceNotFound (exact messages).
    """
    sm = ctx.client("sagemaker")

    experiment_name = ctx.unique_name("sim2real-sm-exp-")
    experiment_arn = sm.create_experiment(
        ExperimentName=experiment_name, Tags=[{"Key": "sim2real", "Value": "1"}]
    )["ExperimentArn"]
    ctx.on_cleanup(lambda: _ignore(lambda: sm.delete_experiment(ExperimentName=experiment_name)))

    trial_name = ctx.unique_name("sim2real-sm-trial-")
    trial_created = sm.create_trial(
        TrialName=trial_name,
        ExperimentName=experiment_name,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    ctx.on_cleanup(lambda: _ignore(lambda: sm.delete_trial(TrialName=trial_name)))

    component_name = ctx.unique_name("sim2real-sm-tc-")
    component_created = sm.create_trial_component(
        TrialComponentName=component_name, Tags=[{"Key": "sim2real", "Value": "1"}]
    )
    ctx.on_cleanup(
        lambda: _ignore(lambda: sm.delete_trial_component(TrialComponentName=component_name))
    )

    # Before association: the component is not (yet) part of the trial.
    before = sm.list_trial_components(TrialName=trial_name)["TrialComponentSummaries"]
    assert before == [], f"expected no components before association, got {before!r}"

    assoc = sm.associate_trial_component(
        TrialComponentName=component_name, TrialName=trial_name
    )
    assert assoc["TrialArn"] == trial_created["TrialArn"], (
        f"expected AssociateTrialComponent to echo the trial's own ARN "
        f"{trial_created['TrialArn']!r}, got {assoc['TrialArn']!r}"
    )
    assert assoc["TrialComponentArn"] == component_created["TrialComponentArn"], (
        f"expected AssociateTrialComponent to echo the component's own ARN "
        f"{component_created['TrialComponentArn']!r}, got {assoc['TrialComponentArn']!r}"
    )

    # Consequence of the association: the component shows up under the trial (the
    # Experiments catalog is a search index, so poll for it to become visible).
    after = _poll_until(
        lambda: sm.list_trial_components(TrialName=trial_name)["TrialComponentSummaries"],
        lambda summaries: len(summaries) == 1,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert after[0]["TrialComponentName"] == component_name, (
        f"expected the associated component {component_name!r} to be the sole entry "
        f"under the trial, got {after!r}"
    )

    described_trial = sm.describe_trial(TrialName=trial_name)
    assert described_trial["TrialName"] == trial_name, (
        f"expected DescribeTrial TrialName {trial_name!r}, got {described_trial['TrialName']!r}"
    )
    assert described_trial["ExperimentName"] == experiment_name, (
        f"expected DescribeTrial ExperimentName {experiment_name!r}, "
        f"got {described_trial['ExperimentName']!r}"
    )
    assert described_trial["TrialArn"] == trial_created["TrialArn"], (
        f"expected DescribeTrial TrialArn {trial_created['TrialArn']!r}, "
        f"got {described_trial['TrialArn']!r}"
    )

    # Cascade teardown: disassociate first (DeleteTrialComponent requires it), then delete
    # component, trial, experiment, and confirm nothing is left over.
    sm.disassociate_trial_component(TrialComponentName=component_name, TrialName=trial_name)
    _poll_until(
        lambda: sm.list_trial_components(TrialName=trial_name)["TrialComponentSummaries"],
        lambda summaries: summaries == [],
        timeout_s=60.0,
        interval_s=3.0,
    )

    sm.delete_trial_component(TrialComponentName=component_name)
    sm.delete_trial(TrialName=trial_name)
    sm.delete_experiment(ExperimentName=experiment_name)

    # Delete* returns before the deletion is durable: an immediate Describe* can still
    # succeed for a short window, so poll for the not-found to land rather than asserting
    # on the very next call.
    tc_code, tc_message = _poll_gone(
        lambda: sm.describe_trial_component(TrialComponentName=component_name)
    )
    assert tc_code == "ResourceNotFound", (
        f"expected DescribeTrialComponent on the deleted component to fail with "
        f"ResourceNotFound, got {tc_code!r}"
    )
    assert tc_message == (
        f"Trial component '{component_created['TrialComponentArn']}' does not exist."
    ), (
        f"unexpected DescribeTrialComponent message: {tc_message!r}"
    )
    trial_code, trial_message = _poll_gone(lambda: sm.describe_trial(TrialName=trial_name))
    assert trial_code == "ResourceNotFound", (
        f"expected DescribeTrial on the deleted trial to fail with ResourceNotFound, "
        f"got {trial_code!r}"
    )
    assert trial_message == f"Trial '{trial_created['TrialArn']}' does not exist.", (
        f"unexpected DescribeTrial message: {trial_message!r}"
    )
    exp_code, exp_message = _poll_gone(
        lambda: sm.describe_experiment(ExperimentName=experiment_name)
    )
    assert exp_code == "ResourceNotFound", (
        f"expected DescribeExperiment on the deleted experiment to fail with "
        f"ResourceNotFound, got {exp_code!r}"
    )
    assert exp_message == f"Experiment '{experiment_arn}' does not exist.", (
        f"unexpected DescribeExperiment message: {exp_message!r}"
    )


def _poll_gone(fn, *, timeout_s=60.0, interval_s=3.0):
    """Poll fn() until it is refused; return the refusal's (code, message). Delete* returns
    before the deletion is durable, so a success inside the window is retried, and a success
    that outlasts it raises."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        try:
            last = fn()
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"the deleted resource was still readable after {timeout_s}s: {last!r}")


def _ignore(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
