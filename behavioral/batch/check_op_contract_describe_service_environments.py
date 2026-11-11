"""op-contract-describeServiceEnvironments."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-describeServiceEnvironments"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeServiceEnvironments returns the created environment's full configuration,
    silently omits an unknown name, and rejects a malformed nextToken."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-se-")
    batch.create_service_environment(
        serviceEnvironmentName=name,
        serviceEnvironmentType="SAGEMAKER_TRAINING",
        capacityLimits=[{"maxCapacity": 3, "capacityUnit": "NUM_INSTANCES"}],
        state="ENABLED",
        tags={"sim2real": "true"},
    )

    def _cleanup():
        try:
            batch.update_service_environment(serviceEnvironment=name, state="DISABLED")
            _poll_se_status(ctx, name, {"VALID", "INVALID"})
        except ClientError as exc:
            err = exc.response["Error"]
            if not (
                err["Code"] == "ClientException"
                and "does not exist" in err.get("Message", "")
            ):
                raise
        batch.delete_service_environment(serviceEnvironment=name)

    ctx.on_cleanup(_cleanup)

    se = _poll_se_status(ctx, name, {"VALID"})
    assert se["serviceEnvironmentName"] == name
    assert se["serviceEnvironmentType"] == "SAGEMAKER_TRAINING"
    assert se["capacityLimits"] == [{"maxCapacity": 3, "capacityUnit": "NUM_INSTANCES"}]
    assert se["tags"] == {"sim2real": "true"}

    # An unknown name is silently omitted from the result, not an error.
    empty = batch.describe_service_environments(serviceEnvironments=[ctx.unique_name("sim2real-batch-no-such-se-")])
    assert empty["serviceEnvironments"] == []

    # Error boundary: a malformed nextToken is rejected.
    code, message = _error_code(lambda: batch.describe_service_environments(nextToken="!!not-a-valid-token!!"))
    assert code == "ClientException", f"expected ClientException, got {code!r}"
    assert message == "Error processing next token", f"unexpected message {message!r}"


def _error_code(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises, because
    accepting a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last state={last!r}")


def _poll_se_status(ctx, name, target_statuses, timeout_s=90.0):
    batch = ctx.client("batch")

    def probe():
        r = batch.describe_service_environments(serviceEnvironments=[name])
        ses = r["serviceEnvironments"]
        return ses[0] if ses else None

    return _poll_until(
        probe, lambda se: se is not None and se["status"] in target_statuses, timeout_s=timeout_s, interval_s=2.0
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
