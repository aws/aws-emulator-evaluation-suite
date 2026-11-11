"""concurrent-capacity-reservation-update-race."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-capacity-reservation-update-race"
GROUP = "concurrency"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateCapacityReservation calls against the same ACTIVE reservation resolve
    deterministically to exactly one of the two submitted targetDpus values, with no corrupted
    (e.g. partial/garbled) intermediate value surviving once the reservation restabilizes."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-behav-capres-race-")
    athena.create_capacity_reservation(
        Name=name,
        TargetDpus=4,
        Tags=[{"Key": "sim2real", "Value": "concurrent-capacity-reservation-update-race"}],
    )
    ctx.on_cleanup(lambda: _cleanup_reservation(athena, name))

    _poll_until(
        lambda: _get_status(athena, name),
        lambda s: s in ("ACTIVE", "FAILED"),
        timeout_s=300,
        interval_s=10,
    )
    status = _get_status(athena, name)
    assert status == "ACTIVE", f"expected reservation to settle ACTIVE before racing, got {status!r}"

    candidates = [12, 20]

    def _update(target: int):
        try:
            athena.update_capacity_reservation(Name=name, TargetDpus=target)
            return ("ok", target)
        except Exception as exc:  # noqa: BLE001 - racing call, either outcome is legitimate
            return ("error", _client_error_code(exc))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(_update, candidates))

    assert any(r[0] == "ok" for r in results), f"both racing updates failed: {results}"
    for kind, detail in results:
        if kind == "error":
            assert detail == "InvalidRequestException", (
                f"expected the losing racer to be rejected with InvalidRequestException, got {detail!r} "
                f"(all results: {results})"
            )

    _poll_until(
        lambda: _get_status(athena, name),
        lambda s: s == "ACTIVE",
        timeout_s=300,
        interval_s=10,
    )
    res = athena.get_capacity_reservation(Name=name)["CapacityReservation"]
    assert res["Status"] == "ACTIVE", f"expected reservation to restabilize ACTIVE, got {res['Status']!r}"
    assert res["TargetDpus"] in candidates, f"corrupted TargetDpus after race: {res['TargetDpus']}"
    assert res["AllocatedDpus"] == res["TargetDpus"], (
        f"AllocatedDpus {res['AllocatedDpus']} does not match settled TargetDpus {res['TargetDpus']}"
    )


def _client_error_code(exc: Exception) -> str:
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    raise exc


def _get_status(athena, name: str) -> str:
    return athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _cleanup_reservation(athena, name: str) -> None:
    from botocore.exceptions import ClientError

    # Cancel once the reservation is ACTIVE (PENDING refuses Cancel), delete it once CANCELLED;
    # only an unknown name ("... not found.") counts as already gone.
    cancelled = False
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            status = _get_status(athena, name)
            if status in ("CANCELLED", "FAILED"):
                athena.delete_capacity_reservation(Name=name)
                return
            if status == "ACTIVE" and not cancelled:
                athena.cancel_capacity_reservation(Name=name)
                cancelled = True
        except ClientError as exc:
            if "not found" in exc.response["Error"].get("Message", ""):
                return
            raise
        time.sleep(2)
    raise TimeoutError(f"capacity reservation {name} not deleted within 180s (last status {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
