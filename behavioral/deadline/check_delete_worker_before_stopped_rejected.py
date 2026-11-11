"""delete-worker-before-stopped-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-worker-before-stopped-rejected"
GROUP = "overly-permissive"
SERVICES = ["deadline"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteWorker succeeds for a never-started (CREATED) worker; a worker that has been
    STARTED is rejected with ConflictException ("valid statuses are CREATED, DELETED, STOPPED,
    NOT_RESPONDING", confirmed on real AWS) and left intact; it deletes cleanly once STOPPED."""
    deadline = ctx.client("deadline")

    farm_id = _create_farm_with_retry(ctx, deadline)
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    role_arn = _create_fleet_trust_role(ctx, farm_id)
    fleet_id = _create_fleet_with_retry(
        ctx,
        deadline,
        farmId=farm_id,
        displayName=ctx.unique_name("sim2real-fleet-"),
        roleArn=role_arn,
        maxWorkerCount=2,
        configuration=_customer_managed_fleet_configuration(),
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_fleet(farmId=farm_id, fleetId=fleet_id)))
    _poll_until(
        lambda: deadline.get_fleet(farmId=farm_id, fleetId=fleet_id),
        lambda f: f["status"] != "CREATE_IN_PROGRESS",
        timeout_s=90.0,
        interval_s=3.0,
    )

    # Real AWS's own valid-status list for DeleteWorker includes CREATED: a worker that has
    # never been started deletes cleanly. Establishing this first is what stops this check
    # from being indistinguishable from "DeleteWorker always fails".
    probe_worker_id = deadline.create_worker(farmId=farm_id, fleetId=fleet_id, tags={"sim2real": CHECK})[
        "workerId"
    ]
    deadline.delete_worker(farmId=farm_id, fleetId=fleet_id, workerId=probe_worker_id)
    probe_error = _client_error(
        lambda: deadline.get_worker(farmId=farm_id, fleetId=fleet_id, workerId=probe_worker_id)
    )
    assert probe_error.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {probe_error}"
    assert probe_error.get("Message") == f"Resource of type worker with id {probe_worker_id} does not exist.", (
        f"expected the exact ResourceNotFoundException message, got {probe_error.get('Message')!r}"
    )

    # Break exactly one thing: start a second worker, then try to delete it while STARTED.
    worker_id = deadline.create_worker(farmId=farm_id, fleetId=fleet_id, tags={"sim2real": CHECK})["workerId"]
    deadline.update_worker(
        farmId=farm_id,
        fleetId=fleet_id,
        workerId=worker_id,
        status="STARTED",
        capabilities=_worker_capabilities(),
    )
    _poll_until(
        lambda: deadline.get_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id),
        lambda w: w["status"] == "STARTED",
        timeout_s=30.0,
        interval_s=2.0,
    )

    error = _client_error(lambda: deadline.delete_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id))
    assert error.get("Code") == "ConflictException", f"expected ConflictException, got {error}"
    assert error.get("Message") == (
        f"Request could not be completed. Status STARTED of resource {worker_id} does not permit "
        "the operation. The valid statuses are [CREATED, DELETED, STOPPED, NOT_RESPONDING]"
    ), (
        f"expected the exact ConflictException message, got {error.get('Message')!r}"
    )

    # Effect absent: the worker is still there, still STARTED.
    worker = deadline.get_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id)
    assert worker["status"] == "STARTED", f"expected STARTED, got {worker['status']}"

    # Restore: once the worker reaches STOPPED, the identical delete call succeeds.
    deadline.update_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id, status="STOPPED")
    _poll_until(
        lambda: deadline.get_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id),
        lambda w: w["status"] == "STOPPED",
        timeout_s=30.0,
        interval_s=2.0,
    )
    deadline.delete_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id)
    final_error = _client_error(
        lambda: deadline.get_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id)
    )
    assert final_error.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {final_error}"
    assert final_error.get("Message") == f"Resource of type worker with id {worker_id} does not exist.", (
        f"expected the exact ResourceNotFoundException message, got {final_error.get('Message')!r}"
    )

    # A mutation on the dead id also fails, not just a read.
    mutate_error = _client_error(
        lambda: deadline.update_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id, status="STARTED")
    )
    assert mutate_error.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {mutate_error}"
    assert mutate_error.get("Message") == f"Resource of type worker with id {worker_id} does not exist.", (
        f"expected the exact ResourceNotFoundException message, got {mutate_error.get('Message')!r}"
    )


# ===== helpers =====
def _create_farm_with_retry(ctx, deadline):
    from botocore.exceptions import ClientError

    last_exc = None
    deadline_t = time.monotonic() + 180.0
    while time.monotonic() < deadline_t:
        try:
            return deadline.create_farm(
                displayName=ctx.unique_name("sim2real-farm-"), tags={"sim2real": CHECK}
            )["farmId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "ServiceQuotaExceededException":
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise last_exc


def _safe(fn) -> None:
    """Teardown: done on ResourceNotFoundException/NoSuchEntity; retries ConflictException (a child
    still being released) every 2 s for up to 60 s; raises everything else."""
    deadline_t = time.monotonic() + 60.0
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("NoSuchEntity", "ResourceNotFoundException"):
                return
            if code != "ConflictException" or time.monotonic() >= deadline_t:
                raise
        time.sleep(2)


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not be reported as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 3.0) -> Any:
    deadline_t = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline_t:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _customer_managed_fleet_configuration() -> dict:
    return {
        "customerManaged": {
            "mode": "NO_SCALING",
            "workerCapabilities": {
                "vCpuCount": {"min": 1, "max": 4},
                "memoryMiB": {"min": 1024, "max": 8192},
                "osFamily": "LINUX",
                "cpuArchitectureType": "x86_64",
            },
        }
    }


def _worker_capabilities() -> dict:
    """Open Job Description reserved capability names (attr.worker.*/amount.worker.*) that
    UpdateWorker requires to report before it will accept a STARTED transition, sized within
    the fleet's own customerManaged workerCapabilities range."""
    return {
        "amounts": [
            {"name": "amount.worker.vcpu", "value": 2},
            {"name": "amount.worker.memory", "value": 2048},
        ],
        "attributes": [
            {"name": "attr.worker.os.family", "values": ["linux"]},
            {"name": "attr.worker.cpu.arch", "values": ["x86_64"]},
        ],
    }


def _create_fleet_trust_role(ctx, farm_id: str) -> str:
    iam = ctx.client("iam")
    sts = ctx.client("sts")
    ident = sts.get_caller_identity()
    account_id = ident["Account"]
    partition = ident["Arn"].split(":")[1]
    farm_arn = f"arn:{partition}:deadline:{ctx.region}:{account_id}:farm/{farm_id}"
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowDeadlineCredentialsService",
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {"Service": "credentials.deadline.amazonaws.com"},
                "Condition": {
                    "StringEquals": {"aws:SourceAccount": account_id},
                    "ArnEquals": {"aws:SourceArn": farm_arn},
                },
            }
        ],
    }
    role_name = ctx.unique_name("sim2real-deadline-fleet-role-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
    role_arn = role["Role"]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AWSDeadlineCloud-FleetWorker"
    )
    ctx.on_cleanup(
        lambda: _safe(
            lambda: iam.detach_role_policy(
                RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AWSDeadlineCloud-FleetWorker"
            )
        )
    )
    # IAM propagation is handled by _create_fleet_with_retry's bounded retry on
    # AccessDeniedException/AssumeRole, not by an unconditional sleep here.
    return role_arn


def _create_fleet_with_retry(ctx, deadline, **kwargs) -> str:
    from botocore.exceptions import ClientError

    last_exc = None
    left = ctx.time_left()
    deadline_t = time.monotonic() + (60.0 if left is None else max(1.0, min(60.0, left - 5.0)))
    while time.monotonic() < deadline_t:
        try:
            return deadline.create_fleet(**kwargs)["fleetId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = str(exc)
            if code == "AccessDeniedException" or "AssumeRole" in msg:
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
