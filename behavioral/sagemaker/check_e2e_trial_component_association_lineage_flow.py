"""e2e-trial-component-association-lineage-flow."""
from __future__ import annotations

import time
from typing import Any, Callable

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-trial-component-association-lineage-flow"
GROUP = "e2e"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AssociateTrialComponent makes ListTrialComponents(TrialName) return exactly that component;
    disassociating removes it, and deleting the component, trial and experiment leaves each
    ResourceNotFound to DescribeX."""
    sm = ctx.client("sagemaker")

    experiment_name = ctx.unique_name("sim2real-sm-exp-")
    sm.create_experiment(ExperimentName=experiment_name)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_experiment(ExperimentName=experiment_name)))

    trial_name = ctx.unique_name("sim2real-sm-trial-")
    sm.create_trial(TrialName=trial_name, ExperimentName=experiment_name)
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_trial(TrialName=trial_name)))

    component_name = ctx.unique_name("sim2real-sm-tc-")
    sm.create_trial_component(TrialComponentName=component_name)
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: sm.delete_trial_component(TrialComponentName=component_name))
    )

    baseline = sm.list_trial_components(TrialName=trial_name)["TrialComponentSummaries"]
    assert baseline == [], f"expected no components associated yet, got {baseline}"

    assoc = sm.associate_trial_component(TrialComponentName=component_name, TrialName=trial_name)
    ctx.on_cleanup(
        lambda: _ignore_not_found(
            lambda: sm.disassociate_trial_component(TrialComponentName=component_name, TrialName=trial_name)
        )
    )

    summaries = _poll_until(
        lambda: sm.list_trial_components(TrialName=trial_name)["TrialComponentSummaries"],
        lambda s: any(c["TrialComponentName"] == component_name for c in s),
        timeout_s=30,
        interval_s=2,
    )
    assert len(summaries) == 1, f"expected exactly 1 associated component, got {summaries}"
    assert summaries[0]["TrialComponentArn"] == assoc["TrialComponentArn"], (
        f"listed component ARN {summaries[0]['TrialComponentArn']!r} does not match "
        f"AssociateTrialComponent's {assoc['TrialComponentArn']!r}"
    )

    trial_desc = sm.describe_trial(TrialName=trial_name)
    assert trial_desc["TrialArn"] == assoc["TrialArn"], (
        f"DescribeTrial ARN {trial_desc['TrialArn']!r} does not match AssociateTrialComponent's "
        f"{assoc['TrialArn']!r}"
    )
    assert trial_desc["ExperimentName"] == experiment_name, (
        f"expected DescribeTrial to report parent experiment {experiment_name!r}, "
        f"got {trial_desc['ExperimentName']!r}"
    )

    # DeleteTrialComponent requires the component to be disassociated first.
    sm.disassociate_trial_component(TrialComponentName=component_name, TrialName=trial_name)
    after_disassoc = _poll_until(
        lambda: sm.list_trial_components(TrialName=trial_name)["TrialComponentSummaries"],
        lambda s: not any(c["TrialComponentName"] == component_name for c in s),
        timeout_s=30,
        interval_s=2,
    )
    assert not any(c["TrialComponentName"] == component_name for c in after_disassoc), (
        f"disassociated component {component_name!r} still listed under the trial: {after_disassoc}"
    )

    sm.delete_trial_component(TrialComponentName=component_name)
    sm.delete_trial(TrialName=trial_name)
    sm.delete_experiment(ExperimentName=experiment_name)

    tc_code, tc_message = _refusal_eventually(
        lambda: sm.describe_trial_component(TrialComponentName=component_name), timeout_s=60, interval_s=3
    )
    assert tc_code == "ResourceNotFound", f"expected ResourceNotFound for deleted component, got {tc_code!r}"
    expected = (
        f"Trial component 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:experiment-trial-component/{component_name}' "
        f"does not exist."
    )
    assert tc_message == expected, f"expected message {expected!r}, got {tc_message!r}"
    trial_code, trial_message = _refusal_eventually(
        lambda: sm.describe_trial(TrialName=trial_name), timeout_s=60, interval_s=3
    )
    assert trial_code == "ResourceNotFound", f"expected ResourceNotFound for deleted trial, got {trial_code!r}"
    expected = f"Trial 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:experiment-trial/{trial_name}' does not exist."
    assert trial_message == expected, f"expected message {expected!r}, got {trial_message!r}"
    exp_code, exp_message = _refusal_eventually(
        lambda: sm.describe_experiment(ExperimentName=experiment_name), timeout_s=60, interval_s=3
    )
    assert exp_code == "ResourceNotFound", f"expected ResourceNotFound for deleted experiment, got {exp_code!r}"
    expected = f"Experiment 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:experiment/{experiment_name}' does not exist."
    assert exp_message == expected, f"expected message {expected!r}, got {exp_message!r}"




def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _refusal_eventually(fn, *, timeout_s, interval_s):
    """Poll fn() until it is refused; return the refusal's (code, message). A call that still
    SUCCEEDS at the deadline raises: the deleted resource must stop being describable."""
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


def _ignore_not_found(fn: Callable[[], Any]) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
