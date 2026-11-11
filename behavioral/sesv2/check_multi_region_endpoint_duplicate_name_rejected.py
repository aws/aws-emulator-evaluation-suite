"""multi-region-endpoint-duplicate-name-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "multi-region-endpoint-duplicate-name-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateMultiRegionEndpoint with an in-use name fails AlreadyExistsException without a second
    endpoint; once the holder is deleted, the same name can be created again."""
    sesv2 = ctx.client("sesv2")
    name = ctx.unique_name("sim2real-mre-")
    secondary = _secondary_region(ctx.region)
    details = {"RoutesDetails": [{"Region": secondary}]}
    creation_tags = [{"Key": "sim2real-behav", "Value": CHECK}]

    sesv2.create_multi_region_endpoint(EndpointName=name, Details=details, Tags=creation_tags)
    ctx.on_cleanup(lambda: _safe_delete_mre(sesv2, name))

    err = _error(lambda: sesv2.create_multi_region_endpoint(EndpointName=name, Details=details))
    assert err == ("AlreadyExistsException", "Endpoint already exists."), (
        f"expected AlreadyExistsException, got {err!r}"
    )

    matches = [e for e in _list_all_endpoints(sesv2) if e["EndpointName"] == name]
    assert len(matches) == 1, "duplicate CreateMultiRegionEndpoint must not create a second endpoint"

    # Deleting an endpoint still CREATING is a different error, so wait for READY first.
    holder_status = _wait_for_status(sesv2, name, {"READY", "FAILED"}, timeout_s=300.0)
    assert holder_status == "READY", f"expected endpoint to become READY, got {holder_status}"

    sesv2.delete_multi_region_endpoint(EndpointName=name)
    _wait_for_not_found(sesv2, name, timeout_s=180.0)

    sesv2.create_multi_region_endpoint(EndpointName=name, Details=details, Tags=creation_tags)
    status = _wait_for_status(sesv2, name, {"READY", "FAILED"}, timeout_s=300.0)
    assert status == "READY", f"expected recreated endpoint to become READY, got {status}"


def _secondary_region(primary: str) -> str:
    # RoutesDetails must name a region distinct from the client's primary region.
    return "us-west-2" if primary != "us-west-2" else "us-east-1"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


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


def _list_all_endpoints(sesv2) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = sesv2.list_multi_region_endpoints(**kwargs)
        out.extend(resp.get("MultiRegionEndpoints", []))
        token = resp.get("NextToken")
        if not token:
            break
    return out


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
