"""worker-status-lifecycle-to-stopped."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "worker-status-lifecycle-to-stopped"
GROUP = "state-machine"
SERVICES = ["deadline"]


def _mgmt_tags() -> dict:
    return {"sim2real:managed": "true", "sim2real:prefix": "sim2real-worker-test"}


def _worker_capabilities() -> dict:
    """Within the fleet's customerManaged range (vCpuCount 1-4, memoryMiB 1024-8192,
    LINUX/x86_64); UpdateWorker rejects a status transition with ValidationException
    ("Required parameter capabilities is missing") when this is omitted."""
    return {
        "amounts": [
            {"name": "amount.worker.vcpu", "value": 2.0},
            {"name": "amount.worker.memory", "value": 2048.0},
        ],
        "attributes": [
            {"name": "attr.worker.os.family", "values": ["linux"]},
            {"name": "attr.worker.cpu.arch", "values": ["x86_64"]},
        ],
    }


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A worker moves CREATED -> STARTED -> STOPPED as UpdateWorker drives it, and only a
    STOPPED worker can be deleted."""
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
        maxWorkerCount=1,
        configuration=_customer_managed_fleet_configuration(),
        tags=_mgmt_tags(),
    )
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_fleet(farmId=farm_id, fleetId=fleet_id)))
    _poll_until(
        lambda: deadline.get_fleet(farmId=farm_id, fleetId=fleet_id),
        lambda f: f["status"] != "CREATE_IN_PROGRESS",
        timeout_s=90.0,
        interval_s=3.0,
    )

    worker_id = deadline.create_worker(farmId=farm_id, fleetId=fleet_id, tags=_mgmt_tags())["workerId"]

    worker = deadline.get_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id)
    assert worker["status"] == "CREATED", f"expected CREATED, got {worker['status']}"

    deadline.update_worker(
        farmId=farm_id,
        fleetId=fleet_id,
        workerId=worker_id,
        status="STARTED",
        capabilities=_worker_capabilities(),
    )
    worker = _poll_until(
        lambda: deadline.get_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id),
        lambda w: w["status"] != "CREATED",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert worker["status"] == "STARTED", f"expected STARTED, got {worker['status']}"

    deadline.update_worker(
        farmId=farm_id,
        fleetId=fleet_id,
        workerId=worker_id,
        status="STOPPED",
        capabilities=_worker_capabilities(),
    )
    worker = _poll_until(
        lambda: deadline.get_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id),
        lambda w: w["status"] == "STOPPED",
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert worker["status"] == "STOPPED", f"expected STOPPED, got {worker['status']}"

    deadline.delete_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id)
    error = _client_error(lambda: deadline.get_worker(farmId=farm_id, fleetId=fleet_id, workerId=worker_id))
    assert error.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {error}"
    assert error.get("Message") == f"Resource of type worker with id {worker_id} does not exist.", (
        f"expected the exact ResourceNotFoundException message, got {error.get('Message')!r}"
    )

    # Gone and unusable: a mutation that worked earlier on this same worker id now fails too.
    mutate_error = _client_error(
        lambda: deadline.update_worker(
            farmId=farm_id,
            fleetId=fleet_id,
            workerId=worker_id,
            status="STARTED",
            capabilities=_worker_capabilities(),
        )
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
                displayName=ctx.unique_name("sim2real-farm-"), tags=_mgmt_tags()
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
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchEntity", "ResourceNotFoundException"):
            raise


def _client_error(fn) -> dict:
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because a
    backend accepting a call real AWS refuses must not be reported as a mere code mismatch."""
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
        Tags=[{"Key": k, "Value": v} for k, v in _mgmt_tags().items()],
    )
    role_arn = role["Role"]["Arn"]
    # Cleanups run last-registered first: the policy is detached before the role is deleted.
    ctx.on_cleanup(lambda: _safe(lambda: iam.delete_role(RoleName=role_name)))
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
    return role_arn


def _create_fleet_with_retry(ctx, deadline, **kwargs) -> str:
    # IAM role + policy attachment propagation is bounded here, not by an unconditional sleep:
    # create_fleet is retried against the live IAM state until the role is assumable or the deadline expires.
    from botocore.exceptions import ClientError

    last_exc = None
    deadline_t = time.monotonic() + 120.0
    while time.monotonic() < deadline_t:
        try:
            return deadline.create_fleet(**kwargs)["fleetId"]
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = str(exc)
            if code == "AccessDeniedException" or "AssumeRole" in msg:
                last_exc = exc
                time.sleep(5)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
