"""experiment-create-describe-delete."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "experiment-create-describe-delete"
GROUP = 'lifecycle'
SERVICES = ['sagemaker']

def _create_experiment(ctx, name=None, display_name="behav-experiment"):
    sm = ctx.client("sagemaker")
    name = name or ctx.unique_name("sim2real-behav-experiment-")
    arn = sm.create_experiment(ExperimentName=name, DisplayName=display_name)["ExperimentArn"]
    ctx.on_cleanup(lambda: _delete_experiment_best_effort(sm, name))
    return name, arn

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateExperiment -> Describe echoes identity -> Delete returns the ARN -> an
    independent Describe of the same name now raises ResourceNotFound."""
    sm = ctx.client("sagemaker")
    name, arn = _create_experiment(ctx, display_name="behav-lifecycle")

    desc = sm.describe_experiment(ExperimentName=name)
    assert desc["ExperimentArn"] == arn, desc
    assert desc["ExperimentName"] == name, desc

    resp = sm.delete_experiment(ExperimentName=name)
    assert resp["ExperimentArn"] == arn, resp

    code, message = _error(lambda: sm.describe_experiment(ExperimentName=name))
    assert code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {code}"
    expected = f"Experiment '{arn}' does not exist."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its (code, message). A success raises: the call must be refused."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_experiment_best_effort(sm, name) -> None:
    try:
        sm.delete_experiment(ExperimentName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
