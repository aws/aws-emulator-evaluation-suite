"""put-capacity-assignment-configuration-serializes-concurrent-writes."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-capacity-assignment-configuration-serializes-concurrent-writes"
GROUP = "concurrency"
SERVICES = ["athena"]

_RACER_COUNT = 5

# Shared teardown deadline (seconds) for every cleanup in one run.
_TEARDOWN_RETRY_S = 900.0


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent PutCapacityAssignmentConfiguration calls against the same reservation are
    serialized: GetCapacityAssignmentConfiguration afterwards always returns exactly one
    of the submitted full configurations, never a merge of two racers' workgroup lists."""
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    athena = ctx.client("athena")
    # Workgroups first, so the LIFO teardown cancels and deletes the reservation before them.
    workgroups = [_sql_workgroup(ctx, teardown_deadline) for _ in range(_RACER_COUNT)]
    reservation_name = ctx.unique_name("sim2real-athena-capres-")
    _try_create_capacity_reservation(ctx, reservation_name, 4, teardown_deadline)

    candidate_configs = [
        {"CapacityAssignments": [{"WorkGroupNames": [wg]}]} for wg in workgroups
    ]

    def _writer(config):
        athena.put_capacity_assignment_configuration(
            CapacityReservationName=reservation_name,
            CapacityAssignments=config["CapacityAssignments"],
        )
        return config

    with ThreadPoolExecutor(max_workers=_RACER_COUNT) as pool:
        futures = [pool.submit(_writer, cfg) for cfg in candidate_configs]
        results = []
        errors = []
        for fut in as_completed(futures):
            try:
                results.append(fut.result())
            except ClientError as exc:
                errors.append(exc)

    assert not errors, f"unexpected writer failures: {errors}"
    assert len(results) == _RACER_COUNT, (
        f"expected all {_RACER_COUNT} racing writers to complete, got {len(results)}: {results}"
    )

    final = athena.get_capacity_assignment_configuration(CapacityReservationName=reservation_name)[
        "CapacityAssignmentConfiguration"
    ]
    assignments = final["CapacityAssignments"]
    assert len(assignments) == 1, f"expected exactly one assignment group, got {assignments}"
    final_workgroups = assignments[0]["WorkGroupNames"]
    assert final_workgroups in [[wg] for wg in workgroups], (
        f"final config {final_workgroups} was not any single racer's submitted config"
    )


def _try_create_capacity_reservation(ctx, name, target_dpus, teardown_deadline):
    athena = ctx.client("athena")
    athena.create_capacity_reservation(
        Name=name,
        TargetDpus=target_dpus,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _cleanup_capacity_reservation(ctx, name, teardown_deadline))


def _cleanup_capacity_reservation(ctx, name, teardown_deadline):
    athena = ctx.client("athena")
    deadline = min(time.monotonic() + 300, teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S))
    cancel_sent = False
    while True:
        try:
            status = athena.get_capacity_reservation(Name=name)["CapacityReservation"]["Status"]
        except ClientError as exc:
            if not _not_found(exc):
                raise
            return
        if status in ("CANCELLED", "FAILED"):
            break
        if status == "ACTIVE" and not cancel_sent:
            athena.cancel_capacity_reservation(Name=name)
            cancel_sent = True
        if time.monotonic() >= deadline:
            raise AssertionError(f"capacity reservation {name} still {status!r} after 300s of cancelling")
        time.sleep(2)
    try:
        athena.delete_capacity_reservation(Name=name)
    except ClientError as exc:
        if not _not_found(exc):
            raise


def _not_found(exc: ClientError) -> bool:
    """Athena reports a missing resource as ResourceNotFoundException or an InvalidRequestException saying so."""
    err = exc.response["Error"]
    msg = err.get("Message", "")
    return err.get("Code") == "ResourceNotFoundException" or (
        err.get("Code") == "InvalidRequestException" and ("not found" in msg or "does not exist" in msg)
    )


def _sql_workgroup(ctx, teardown_deadline):
    athena = ctx.client("athena")
    name = ctx.unique_name("sim2real-athena-sql-wg-")
    athena.create_work_group(Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(lambda: _delete_work_group(athena, name, teardown_deadline))
    return name


def _delete_work_group(athena, name, teardown_deadline):
    """Delete the workgroup, retrying while it is still assigned to the reservation being removed."""
    deadline = teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S)
    while True:
        try:
            athena.delete_work_group(WorkGroup=name, RecursiveDeleteOption=True)
            return
        except ClientError as exc:
            if _not_found(exc):
                return
            err = exc.response["Error"]
            assigned = err.get("Code") == "InvalidRequestException" and (
                "assigned to a reservation" in err.get("Message", "")
            )
            if not assigned or time.monotonic() >= deadline:
                raise
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
