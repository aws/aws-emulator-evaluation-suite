"""multi-region-endpoint-concurrent-delete-race-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multi-region-endpoint-concurrent-delete-race-rejected"
GROUP = "concurrency"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second DeleteMultiRegionEndpoint during an in-progress delete fails
    ConcurrentModificationException; the endpoint reads DELETING, then NotFoundException."""
    sesv2 = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-mre-")
    secondary = _secondary_region(ctx.region)

    sesv2.create_multi_region_endpoint(
        EndpointName=name,
        Details={"RoutesDetails": [{"Region": secondary}]},
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:prefix", "Value": "sim2real-behav"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_mre(sesv2, name))

    status = _wait_for_status(sesv2, name, {"READY", "FAILED"}, timeout_s=300.0)
    assert status == "READY", f"expected endpoint to become READY, got {status}"

    # Deletion is asynchronous, so a delete issued right after the first lands in its window.
    sesv2.delete_multi_region_endpoint(EndpointName=name)
    code, message = _error(lambda: sesv2.delete_multi_region_endpoint(EndpointName=name))
    assert code == "ConcurrentModificationException", (
        f"expected the competing delete to fail with ConcurrentModificationException, got {code!r}: {message!r}"
    )
    expected = "Unable to delete resource in DEPROVISIONING status."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    after = sesv2.get_multi_region_endpoint(EndpointName=name)
    assert after["Status"] == "DELETING", (
        f"expected the endpoint to read DELETING inside the window, got {after['Status']!r}"
    )
    code, message = _wait_until_gone(sesv2, name, timeout_s=300.0)
    assert code == "NotFoundException", f"expected NotFoundException once deleted, got {code!r}: {message!r}"
    # The 404 body carries a null message.
    assert message is None, f"expected a null message, got {message!r}"


def _secondary_region(primary: str) -> str:
    # RoutesDetails must name a region distinct from the client's primary region.
    return "us-west-2" if primary != "us-west-2" else "us-east-1"


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _wait_until_gone(sesv2, name: str, timeout_s: float = 300.0, interval_s: float = 5.0) -> tuple[str, str]:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        try:
            status = sesv2.get_multi_region_endpoint(EndpointName=name)["Status"]
        except ClientError as err:
            return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {name} still present after {timeout_s}s (last={status})")


def _wait_for_status(sesv2, name: str, terminal: set[str], timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = sesv2.get_multi_region_endpoint(EndpointName=name)["Status"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {name} never reached {terminal} within {timeout_s}s (last={status})")


def _safe_delete_mre(sesv2, name: str) -> None:
    deadline = time.monotonic() + 120.0
    while time.monotonic() < deadline:
        try:
            status = sesv2.get_multi_region_endpoint(EndpointName=name)["Status"]
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        if status != "CREATING":
            break
        time.sleep(5.0)
    try:
        sesv2.delete_multi_region_endpoint(EndpointName=name)
    except ClientError as err:
        if err.response["Error"]["Code"] not in ("NotFoundException", "ConcurrentModificationException"):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
