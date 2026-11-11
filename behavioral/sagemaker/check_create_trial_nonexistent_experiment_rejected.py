"""create-trial-nonexistent-experiment-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-trial-nonexistent-experiment-rejected"
GROUP = "e2e"
SERVICES = ["sagemaker"]

_MANAGED_TAGS = [{"Key": "sim2real:managed", "Value": "true"}]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTrial against an ExperimentName that does not exist is rejected with
    ResourceNotFound, no trial is created, and the same call succeeds once a real
    experiment backs it (positive control)."""
    sm = ctx.client("sagemaker")

    bogus_experiment = ctx.unique_name("sim2real-noexist-exp-")
    trial_name = ctx.unique_name("sim2real-trial-")

    code, message = _error(lambda: sm.create_trial(TrialName=trial_name, ExperimentName=bogus_experiment))
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}"
    expected = (
        f"Experiment 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:experiment/{bogus_experiment}' "
        "does not exist."
    )
    assert message == expected, f"expected {expected!r}, got {message!r}"

    # effect absent: no trial was actually created under that name.
    not_found_code, not_found_message = _error(lambda: sm.describe_trial(TrialName=trial_name))
    assert not_found_code == "ResourceNotFound", (
        f"a trial should not exist after the rejected create, got describe code {not_found_code!r}"
    )
    expected_absent = (
        f"Trial 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:experiment-trial/{trial_name}' "
        "does not exist."
    )
    assert not_found_message == expected_absent, (
        f"expected {expected_absent!r}, got {not_found_message!r}"
    )

    # --- positive control: the identical call succeeds against a real experiment ---
    real_experiment = ctx.unique_name("sim2real-exp-")
    sm.create_experiment(ExperimentName=real_experiment, Tags=_MANAGED_TAGS)
    ctx.on_cleanup(lambda: sm.delete_experiment(ExperimentName=real_experiment))

    sm.create_trial(TrialName=trial_name, ExperimentName=real_experiment, Tags=_MANAGED_TAGS)
    ctx.on_cleanup(lambda: sm.delete_trial(TrialName=trial_name))

    described = sm.describe_trial(TrialName=trial_name)
    assert described["ExperimentName"] == real_experiment


def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
