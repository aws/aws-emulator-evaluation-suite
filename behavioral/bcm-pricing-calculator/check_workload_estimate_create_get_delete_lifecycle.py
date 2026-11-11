"""workload-estimate-create-get-delete-lifecycle."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "workload-estimate-create-get-delete-lifecycle"
GROUP = "lifecycle"
SERVICES = ["bcm-pricing-calculator"]

NOT_FOUND_MESSAGE = "The requested WorkloadEstimate was not found. Check the WorkloadEstimate ID and try again."


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateWorkloadEstimate reaches a terminal status with a zero baseline cost, then Delete removes it."""
    client = ctx.client("bcm-pricing-calculator")
    name = ctx.unique_name("sim2real-we-")

    created = client.create_workload_estimate(name=name)
    estimate_id = created["id"]
    ctx.on_cleanup(lambda: _delete_workload_estimate(client, estimate_id))

    assert created["name"] == name, f"expected created name {name!r}, got {created['name']!r}"

    final = _poll_until(
        lambda: client.get_workload_estimate(identifier=estimate_id),
        lambda r: r["status"] != "UPDATING",
        timeout_s=90.0,
        interval_s=3.0,
    )
    # With no usage ever added, a workload estimate settles VALID with zero cost.
    assert final["status"] == "VALID", f"expected terminal status VALID, got {final['status']!r}"
    assert final["totalCost"] == 0.0, f"expected zero-usage cost 0.0, got {final['totalCost']!r}"
    assert final["costCurrency"] == "USD", f"expected costCurrency USD, got {final['costCurrency']!r}"

    client.delete_workload_estimate(identifier=estimate_id)

    code, message = _error_code_and_message(lambda: client.get_workload_estimate(identifier=estimate_id))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code!r}"
    assert message == NOT_FOUND_MESSAGE, f"expected {NOT_FOUND_MESSAGE!r} after delete, got {message!r}"


# ===== helpers =====
def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded with {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _delete_workload_estimate(client, estimate_id):
    """Delete the estimate unless Get already reports it gone; any other error raises."""
    from botocore.exceptions import ClientError

    try:
        client.get_workload_estimate(identifier=estimate_id)
    except ClientError as err:
        if err.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    client.delete_workload_estimate(identifier=estimate_id)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
