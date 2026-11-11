"""multi-region-endpoint-create-get-list-delete-lifecycle."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multi-region-endpoint-create-get-list-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A created multi-region endpoint transitions CREATING->READY, is visible via
    GetMultiRegionEndpoint and ListMultiRegionEndpoints, and is fully gone (from both APIs)
    after DeleteMultiRegionEndpoint completes."""
    sesv2 = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-mre-")
    # A multi-region endpoint's secondary must be a real, distinct AWS region (there is no
    # sandbox/fake region for this), so region literals here are inherent to the resource
    # under test, not an environment shortcut.
    secondary = _secondary_region(ctx.region)

    sesv2.create_multi_region_endpoint(
        EndpointName=name,
        Details={"RoutesDetails": [{"Region": secondary}]},
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _safe_delete_mre(sesv2, name))

    # Multi-region endpoint provisioning synchronizes identities/config sets across two
    # regions and is documented as asynchronous; poll for the real CREATING->READY transition.
    status = _wait_for_status(sesv2, name, {"READY", "FAILED"}, timeout_s=300.0)
    assert status == "READY", f"expected endpoint to become READY, got {status}"

    got = sesv2.get_multi_region_endpoint(EndpointName=name)
    assert got["EndpointName"] == name, f"expected EndpointName {name!r}, got {got['EndpointName']!r}"
    assert got["EndpointId"], f"expected a non-empty EndpointId, got {got['EndpointId']!r}"
    assert got["Status"] == "READY", f"expected Status READY after transition, got {got['Status']!r}"

    names = _list_all_endpoint_names(sesv2)
    assert name in names, "newly created endpoint did not appear in ListMultiRegionEndpoints"

    sesv2.delete_multi_region_endpoint(EndpointName=name)
    _wait_for_not_found(sesv2, name, timeout_s=180.0)

    names_after = _list_all_endpoint_names(sesv2)
    assert name not in names_after, "deleted endpoint still visible in ListMultiRegionEndpoints"


def _secondary_region(primary: str) -> str:
    return "us-west-2" if primary != "us-west-2" else "us-east-1"


def _wait_for_status(sesv2, name: str, terminal: set[str], timeout_s: float = 300.0, interval_s: float = 10.0) -> str:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = sesv2.get_multi_region_endpoint(EndpointName=name)["Status"]
        if status in terminal:
            return status
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {name} never reached {terminal} within {timeout_s}s (last={status})")


def _wait_for_not_found(sesv2, name: str, timeout_s: float = 180.0, interval_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            sesv2.get_multi_region_endpoint(EndpointName=name)
        except ClientError as err:
            if err.response["Error"]["Code"] == "NotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"endpoint {name} was not removed within {timeout_s}s")


def _list_all_endpoint_names(sesv2) -> set[str]:
    names: set[str] = set()
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = sesv2.list_multi_region_endpoints(**kwargs)
        for ep in resp.get("MultiRegionEndpoints", []):
            names.add(ep["EndpointName"])
        token = resp.get("NextToken")
        if not token:
            break
    return names


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
