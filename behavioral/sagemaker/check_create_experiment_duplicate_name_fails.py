"""create-experiment-duplicate-name-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-experiment-duplicate-name-fails"
GROUP = 'overly-permissive'
SERVICES = ['sagemaker']

def _create_experiment(ctx, name=None, display_name="behav-experiment"):
    sm = ctx.client("sagemaker")
    name = name or ctx.unique_name("sim2real-behav-experiment-")
    arn = sm.create_experiment(
        ExperimentName=name,
        DisplayName=display_name,
        Tags=[{"Key": "sim2real", "Value": "behavioral-check"}],
    )["ExperimentArn"]
    ctx.on_cleanup(lambda: _delete_experiment_if_present(sm, name))
    return name, arn


def _delete_experiment_if_present(sm, name):
    """Teardown: the run deletes and re-creates the same name, so the first registration
    can find it already gone; only a ResourceNotFound is tolerated."""
    try:
        sm.delete_experiment(ExperimentName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFound":
            raise


def _reject(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises — an emulator
    ACCEPTING a call real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected rejection, but the call succeeded and returned {result!r}")


_STILL_PRESENT = "<call succeeded>"


def _error_code_or_present(fn):
    """Call fn(); return its error code, or the ``_STILL_PRESENT`` sentinel (a value no
    error code can equal) on success. Unlike ``_reject``, a success is a valid intermediate
    poll state here, not a defect to raise on."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    return _STILL_PRESENT


def _poll_until(probe, predicate, *, timeout_s, interval_s=2.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not observed within {timeout_s}s; last saw {last!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second CreateExperiment with an in-use name fails with ValidationException and the exact
    message and leaves the original untouched, and after deletion the identical call creates a new
    experiment with a later CreationTime."""
    sm = ctx.client("sagemaker")
    name, arn = _create_experiment(ctx)
    assert arn, "positive control: the first CreateExperiment must succeed and return an ARN"

    code, message = _reject(lambda: sm.create_experiment(ExperimentName=name))
    assert code == "ValidationException", f"expected ValidationException for a duplicate name, got {code!r}"
    assert message == (
        "Experiment names must be unique within an AWS account and region. "
        f"Experiment with name ({name}) already exists."
    ), f"unexpected duplicate-name message: {message!r}"

    # Effect-absent: an independent read shows the name still resolves to the ORIGINAL
    # experiment — the rejected duplicate never took effect.
    described = sm.describe_experiment(ExperimentName=name)
    assert described["ExperimentArn"] == arn, (
        f"duplicate create must leave the original experiment {arn!r} untouched, "
        f"but describe now returns {described.get('ExperimentArn')!r}"
    )

    # Restore: free the name for real by deleting the original, then confirm it is gone
    # via an independent read before relying on that state.
    sm.delete_experiment(ExperimentName=name)

    def _describe_code():
        return _error_code_or_present(lambda: sm.describe_experiment(ExperimentName=name))

    _poll_until(
        _describe_code,
        lambda code: code == "ResourceNotFound",
        timeout_s=30.0,
        description=f"experiment {name!r} deleted",
    )

    # The identical call succeeds once the name is free. The ARN is derived from the name, so the
    # evidence that this is a new object, not a stale read, is a later CreationTime.
    name2, arn2 = _create_experiment(ctx, name=name)

    described2 = sm.describe_experiment(ExperimentName=name2)
    assert described2["ExperimentArn"] == arn2, (
        f"expected the recreated experiment {arn2!r} to be visible via an independent read, "
        f"got {described2.get('ExperimentArn')!r}"
    )
    assert described2["CreationTime"] > described["CreationTime"], (
        f"expected the recreated experiment's CreationTime {described2['CreationTime']!r} to be "
        f"strictly after the original's {described['CreationTime']!r} — proof this is a new object, "
        f"not a stale read of the deleted one"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
