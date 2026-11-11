"""queue-fleet-association-delete-before-stopped-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "queue-fleet-association-delete-before-stopped-rejected"
GROUP = "overly-permissive"
SERVICES = ["deadline"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteQueueFleetAssociation is rejected with ConflictException while the association is
    still ACTIVE; the association is left intact, and it deletes cleanly once STOPPED."""
    deadline = ctx.client("deadline")

    farm_id = _create_farm_with_retry(ctx, deadline)
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    queue_id = deadline.create_queue(
        farmId=farm_id,
        displayName=ctx.unique_name("sim2real-queue-"),
        jobRunAsUser={"runAs": "WORKER_AGENT_USER"},
        tags={"sim2real": CHECK},
    )["queueId"]
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_queue(farmId=farm_id, queueId=queue_id)))

    role_arn = _create_fleet_trust_role(ctx, farm_id)
    fleet_id = _create_fleet_with_retry(
        ctx,
        deadline,
        farmId=farm_id,
        displayName=ctx.unique_name("sim2real-fleet-"),
        roleArn=role_arn,
        maxWorkerCount=1,
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

    deadline.create_queue_fleet_association(farmId=farm_id, queueId=queue_id, fleetId=fleet_id)

    # Break exactly one thing: try to delete the association while it is still ACTIVE.
    error = _client_error(
        lambda: deadline.delete_queue_fleet_association(farmId=farm_id, queueId=queue_id, fleetId=fleet_id)
    )
    assert error.get("Code") == "ConflictException", f"expected ConflictException, got {error}"
    assert error.get("Message") == "QueueFleetAssociation is in ACTIVE status and cannot be deleted.", (
        f"expected the exact ConflictException message, got {error.get('Message')!r}"
    )

    # Effect absent: the association is still there, still ACTIVE.
    assoc = deadline.get_queue_fleet_association(farmId=farm_id, queueId=queue_id, fleetId=fleet_id)
    assert assoc["status"] == "ACTIVE", f"expected association to remain ACTIVE, got {assoc['status']}"

    # Positive control: once stopped, the same delete call succeeds.
    deadline.update_queue_fleet_association(
        farmId=farm_id, queueId=queue_id, fleetId=fleet_id, status="STOP_SCHEDULING_AND_CANCEL_TASKS"
    )
    _poll_until(
        lambda: deadline.get_queue_fleet_association(farmId=farm_id, queueId=queue_id, fleetId=fleet_id),
        lambda a: a["status"] == "STOPPED",
        timeout_s=120.0,
        interval_s=5.0,
    )
    deadline.delete_queue_fleet_association(farmId=farm_id, queueId=queue_id, fleetId=fleet_id)
    final_error = _client_error(
        lambda: deadline.get_queue_fleet_association(farmId=farm_id, queueId=queue_id, fleetId=fleet_id)
    )
    assert final_error.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {final_error}"
    assert final_error.get("Message") == (
        f"Resource of type queue-fleet-association with id {farm_id}, {queue_id} and {fleet_id} "
        "does not exist."
    ), (
        f"expected the exact ResourceNotFoundException message, got {final_error.get('Message')!r}"
    )

    # Gone means unusable too: a mutation on the dead association also fails not-found.
    mutate_error = _client_error(
        lambda: deadline.update_queue_fleet_association(
            farmId=farm_id, queueId=queue_id, fleetId=fleet_id, status="ACTIVE"
        )
    )
    assert mutate_error.get("Code") == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {mutate_error}"
    assert mutate_error.get("Message") == (
        f"Resource of type queue-fleet-association with id {farm_id}, {queue_id} and {fleet_id} "
        "does not exist."
    ), (
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
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
