"""multi-region-endpoint-get-after-delete-not-found."""
from __future__ import annotations

import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "multi-region-endpoint-get-after-delete-not-found"
GROUP = "state-machine"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMultiRegionEndpoint on a fully deleted endpoint raises NotFoundException, while the
    same call on the live endpoint (positive control) succeeded moments earlier."""
    sesv2 = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-mre-")
    secondary = _secondary_region(ctx.region)

    sesv2.create_multi_region_endpoint(
        EndpointName=name,
        Details={"RoutesDetails": [{"Region": secondary}]},
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_delete_mre(sesv2, name))

    status = _wait_for_status(sesv2, name, {"READY", "FAILED"}, timeout_s=300.0)
    assert status == "READY", f"expected endpoint to become READY, got {status}"

    # Positive control: the live endpoint is retrievable.
    got = sesv2.get_multi_region_endpoint(EndpointName=name)
    assert got["EndpointName"] == name, f"expected EndpointName={name!r}, got {got.get('EndpointName')!r}"

    sesv2.delete_multi_region_endpoint(EndpointName=name)
    # GetMultiRegionEndpoint's NotFoundException carries no message at all; the absence is graded.
    err = _wait_for_not_found(sesv2, name, timeout_s=180.0)
    assert err == ("NotFoundException", None), (
        f"expected a message-less NotFoundException from GetMultiRegionEndpoint after delete, got {err!r}"
    )

    # The deleted id is not just unreadable but unusable: a second mutation on it (DeleteMultiRegionEndpoint,
    # which the model declares can itself raise NotFoundException) must also be rejected, not silently no-op.
    redelete = _error(lambda: sesv2.delete_multi_region_endpoint(EndpointName=name))
    assert redelete == ("NotFoundException", "Endpoint does not exist."), (
        f"expected NotFoundException re-deleting a gone endpoint, got {redelete!r}"
    )


def _secondary_region(primary: str) -> str:
    # CreateMultiRegionEndpoint requires a secondary region distinct from ctx.region (the primary);
    # any second region works, so this literal picks one rather than pinning the target's own region.
    return "us-west-2" if primary != "us-west-2" else "us-east-1"


def _error(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected a ClientError, call unexpectedly succeeded")


def _wait_for_status(sesv2, name: str, terminal: set[str], timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = sesv2.get_multi_region_endpoint(EndpointName=name)["Status"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {name} never reached {terminal} within {timeout_s}s (last={status})")


def _wait_for_not_found(sesv2, name: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> tuple:
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            sesv2.get_multi_region_endpoint(EndpointName=name)
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code == "NotFoundException":
                return last_code, err.response["Error"].get("Message")
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {name} never returned NotFoundException within {timeout_s}s (last={last_code})")


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
