"""concurrent-capacity-reservation-update-race-resolves-consistently."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-capacity-reservation-update-race-resolves-consistently"
GROUP = "concurrency"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateCapacityReservation calls on one ACTIVE reservation settle to exactly
    one of the two racing TargetDpus (no lost update or corrupted merge), and any call rejected
    mid-race gets InvalidRequestException."""
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-athena-cr-")
    athena.create_capacity_reservation(Name=name, TargetDpus=24)
    ctx.on_cleanup(lambda: _safe_cancel(athena, name))

    _poll_until(
        lambda: athena.get_capacity_reservation(Name=name)["CapacityReservation"],
        lambda r: r["Status"] == "ACTIVE",
        timeout_s=600.0,
    )

    targets = [48, 72]

    def _update(target: int):
        try:
            athena.update_capacity_reservation(Name=name, TargetDpus=target)
            return ("ok", None)
        except Exception as exc:  # noqa: BLE001
            return ("error", _client_error_code(exc), exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [f.result() for f in [pool.submit(_update, t) for t in targets]]

    successes = [o for o in outcomes if o[0] == "ok"]
    failures = [o for o in outcomes if o[0] == "error"]
    assert len(successes) >= 1, f"neither concurrent update succeeded: {outcomes}"
    # Which refusal a loser sees depends on how far the winner got; each is AWS's exact wording.
    pending = "Reservation cannot be modified when state is UPDATE_PENDING"
    exists = f"Reservation with name {name} already exists."
    for _, code, message in failures:
        assert code == "InvalidRequestException", f"unexpected rejection code: {code}"
        expected = pending if message.startswith("Reservation cannot ") else exists
        assert message == expected, f"unexpected rejection message: {message!r}"

    final = _poll_until(
        lambda: athena.get_capacity_reservation(Name=name)["CapacityReservation"],
        lambda r: r["Status"] == "ACTIVE",
        timeout_s=600.0,
    )
    assert final["TargetDpus"] in targets, (
        f"final TargetDpus {final['TargetDpus']} matches neither racing target "
        f"{targets} -- lost update or corrupted merge"
    )


def _client_error_code(exc):
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"]
    raise exc


def _safe_cancel(athena, name: str) -> None:
    from botocore.exceptions import ClientError

    # Cancel once the reservation is ACTIVE (PENDING refuses Cancel), delete it once CANCELLED;
    # only an unknown name ("... not found.") counts as already gone.
    cancelled = False
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
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


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 10.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
