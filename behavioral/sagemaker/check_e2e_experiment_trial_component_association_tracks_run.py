"""e2e-experiment-trial-component-association-tracks-run."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "e2e-experiment-trial-component-association-tracks-run"
GROUP = "e2e"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An associated trial component shows up in its trial's ListTrialComponents (DescribeTrial
    does not expose membership); deleting the association, trial and experiment leaves no
    dangling membership or describable resources."""
    sm = ctx.client("sagemaker")

    experiment_name = ctx.unique_name("sim2real-sm-exp-")
    trial_name = ctx.unique_name("sim2real-sm-trial-")
    component_name = ctx.unique_name("sim2real-sm-tc-")
    tags_kv = [{"Key": "sim2real-check", "Value": CHECK}]

    sm.create_experiment(ExperimentName=experiment_name, Tags=tags_kv)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_experiment(ExperimentName=experiment_name)))

    sm.create_trial(TrialName=trial_name, ExperimentName=experiment_name, Tags=tags_kv)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_trial(TrialName=trial_name)))

    sm.create_trial_component(TrialComponentName=component_name, Tags=tags_kv)
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: sm.delete_trial_component(TrialComponentName=component_name)
        )
    )

    before = {
        c["TrialComponentName"]
        for c in sm.list_trial_components(TrialName=trial_name).get(
            "TrialComponentSummaries", []
        )
    }
    assert component_name not in before, (
        f"expected {component_name!r} absent from ListTrialComponents before association, "
        f"got {before!r}"
    )

    assoc = sm.associate_trial_component(
        TrialComponentName=component_name, TrialName=trial_name
    )
    assert assoc["TrialComponentArn"], "AssociateTrialComponent returned no TrialComponentArn"
    assert assoc["TrialArn"], "AssociateTrialComponent returned no TrialArn"

    # ListTrialComponents is backed by an eventually consistent search index, so poll.
    after = _poll_until(
        lambda: {
            c["TrialComponentName"]
            for c in sm.list_trial_components(TrialName=trial_name).get(
                "TrialComponentSummaries", []
            )
        },
        lambda names: component_name in names,
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert component_name in after, (
        f"expected {component_name!r} in ListTrialComponents after association, got {after!r}"
    )

    trial_desc = sm.describe_trial(TrialName=trial_name)
    assert trial_desc["ExperimentName"] == experiment_name, (
        f"expected DescribeTrial ExperimentName {experiment_name!r}, "
        f"got {trial_desc['ExperimentName']!r}"
    )
    assert trial_desc["TrialArn"] == assoc["TrialArn"], (
        f"expected DescribeTrial TrialArn {assoc['TrialArn']!r} to match the association's, "
        f"got {trial_desc['TrialArn']!r}"
    )

    sm.disassociate_trial_component(TrialComponentName=component_name, TrialName=trial_name)
    sm.delete_trial_component(TrialComponentName=component_name)
    sm.delete_trial(TrialName=trial_name)
    sm.delete_experiment(ExperimentName=experiment_name)

    # Describe* can still return 200 right after the matching Delete*, so poll for
    # ResourceNotFound.
    trial_code, trial_message = _refusal_eventually(
        lambda: sm.describe_trial(TrialName=trial_name), timeout_s=60.0, interval_s=3.0
    )
    assert trial_code == "ResourceNotFound", (
        f"expected DescribeTrial on the deleted trial to fail ResourceNotFound, got {trial_code!r}"
    )
    expected = f"Trial 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:experiment-trial/{trial_name}' does not exist."
    assert trial_message == expected, f"expected message {expected!r}, got {trial_message!r}"
    exp_code, exp_message = _refusal_eventually(
        lambda: sm.describe_experiment(ExperimentName=experiment_name), timeout_s=60.0, interval_s=3.0
    )
    assert exp_code == "ResourceNotFound", (
        f"expected DescribeExperiment on the deleted experiment to fail ResourceNotFound, "
        f"got {exp_code!r}"
    )
    expected = f"Experiment 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:experiment/{experiment_name}' does not exist."
    assert exp_message == expected, f"expected message {expected!r}, got {exp_message!r}"
    tc_code, tc_message = _refusal_eventually(
        lambda: sm.describe_trial_component(TrialComponentName=component_name), timeout_s=60.0, interval_s=3.0
    )
    assert tc_code == "ResourceNotFound", (
        f"expected DescribeTrialComponent on the deleted component to fail ResourceNotFound, "
        f"got {tc_code!r}"
    )
    expected = (
        f"Trial component 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:experiment-trial-component/{component_name}' "
        f"does not exist."
    )
    assert tc_message == expected, f"expected message {expected!r}, got {tc_message!r}"


def _refusal_eventually(fn, *, timeout_s, interval_s):
    """Poll fn() until it is refused; return the refusal's (code, message). A call that still
    SUCCEEDS at the deadline raises: the deleted resource must stop being describable."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    result = None
    while time.monotonic() < deadline:
        try:
            result = fn()
        except ClientError as exc:
            err = exc.response["Error"]
            return err["Code"], err.get("Message")
        time.sleep(interval_s)
    raise AssertionError(
        f"expected the call to be rejected within {timeout_s}s, but it still SUCCEEDED and "
        f"returned {result!r}"
    )


def _ignore_not_found(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _poll_until(probe, predicate, *, timeout_s, interval_s):
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
