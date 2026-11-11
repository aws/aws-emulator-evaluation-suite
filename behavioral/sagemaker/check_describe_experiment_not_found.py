"""describe-experiment-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-experiment-not-found"
GROUP = 'error-semantics'
SERVICES = ['sagemaker']

def _error_code_and_message(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(
        f"expected the call to be rejected, but it succeeded and returned {result!r}"
    )

def _swallow(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DescribeExperiment returns ResourceNotFound with its exact message both for a name never created and for a
    deleted experiment, while a live experiment still describes with its own ARN and name.
    """
    sm = ctx.client("sagemaker")

    # Positive control: an Experiment we create and never delete describes
    # fine, in the same run — without this, "rejects a missing Experiment" is
    # indistinguishable from "rejects every DescribeExperiment".
    live_name = ctx.unique_name("sim2real-behav-experiment-live-")
    live_arn = sm.create_experiment(ExperimentName=live_name, DisplayName="behav-live")["ExperimentArn"]
    ctx.on_cleanup(lambda: _swallow(lambda: sm.delete_experiment(ExperimentName=live_name)))
    live_desc = sm.describe_experiment(ExperimentName=live_name)
    assert live_desc["ExperimentArn"] == live_arn, live_desc
    assert live_desc["ExperimentName"] == live_name, live_desc

    # The subject: a name that was never created.
    missing = ctx.unique_name("sim2real-behav-" + "missing-experiment-")
    code, message = _error_code_and_message(
        lambda: sm.describe_experiment(ExperimentName=missing)
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r}: {message!r}"
    expected_missing = f"Experiment 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:experiment/{missing}' does not exist."
    assert message == expected_missing, f"expected {expected_missing!r}, got {message!r}"

    # The same code for a name that existed and was deleted — the deletion is
    # real, not silently ignored.
    deleted_name = ctx.unique_name("sim2real-behav-experiment-deleted-")
    sm.create_experiment(ExperimentName=deleted_name, DisplayName="behav-deleted")
    ctx.on_cleanup(lambda: _swallow(lambda: sm.delete_experiment(ExperimentName=deleted_name)))
    sm.delete_experiment(ExperimentName=deleted_name)
    deleted_code, deleted_message = _error_code_and_message(
        lambda: sm.describe_experiment(ExperimentName=deleted_name)
    )
    assert deleted_code == "ResourceNotFound", (
        f"expected ResourceNotFound, got {deleted_code!r}: {deleted_message!r}"
    )
    expected_deleted = f"Experiment 'arn:aws:sagemaker:{ctx.region}:{ctx.account}:experiment/{deleted_name}' does not exist."
    assert deleted_message == expected_deleted, (
        f"expected {expected_deleted!r}, got {deleted_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
