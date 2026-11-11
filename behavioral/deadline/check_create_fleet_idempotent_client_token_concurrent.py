"""create-fleet-idempotent-client-token-concurrent."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-fleet-idempotent-client-token-concurrent"
GROUP = "concurrency"
SERVICES = ["deadline"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateFleet calls sharing one idempotency clientToken and identical
    parameters all resolve to exactly one fleet (the idempotencyToken contract holds under
    contention), not N distinct fleets."""
    deadline = ctx.client("deadline")

    farm_id = _create_farm_with_retry(ctx, deadline)
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    role_arn = _create_fleet_trust_role(ctx, farm_id)

    client_token = ctx.unique_name("sim2real-tok-")[:64]
    display_name = ctx.unique_name("sim2real-fleet-race-")
    config = _customer_managed_fleet_configuration()

    def _create():
        from botocore.exceptions import ClientError

        last_exc = None
        left = ctx.time_left()
        deadline_t = time.monotonic() + (80.0 if left is None else max(1.0, min(80.0, left - 5.0)))
        while time.monotonic() < deadline_t:
            try:
                return deadline.create_fleet(
                    farmId=farm_id,
                    clientToken=client_token,
                    displayName=display_name,
                    roleArn=role_arn,
                    maxWorkerCount=1,
                    configuration=config,
                )["fleetId"]
            except ClientError as exc:
                code = exc.response.get("Error", {}).get("Code")
                msg = str(exc)
                if code == "AccessDeniedException" or "AssumeRole" in msg:
                    # the just-created trust role/policy attachment propagates to the
                    # credentials service within the 80 s deadline
                    last_exc = exc
                    time.sleep(2)
                    continue
                if code == "ThrottlingException":
                    # 5 racers issuing CreateFleet at once can exceed the API's own TPS
                    # limit even after botocore's built-in retries
                    last_exc = exc
                    time.sleep(2)
                    continue
                raise
        raise last_exc

    n_racers = 5
    with ThreadPoolExecutor(max_workers=n_racers) as pool:
        futures = [pool.submit(_create) for _ in range(n_racers)]
        fleet_ids = [f.result() for f in as_completed(futures)]

    assert len(fleet_ids) == n_racers, f"expected {n_racers} racer results, got {len(fleet_ids)}"
    distinct = set(fleet_ids)
    assert len(distinct) == 1, f"expected exactly 1 distinct fleetId, got {distinct}"

    fleet_id = distinct.pop()
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_fleet(farmId=farm_id, fleetId=fleet_id)))

    matching = [f for f in deadline.list_fleets(farmId=farm_id)["fleets"] if f["displayName"] == display_name]
    assert len(matching) == 1, f"expected exactly one fleet with that name, found {len(matching)}"

    from botocore.exceptions import ClientError

    deadline.delete_fleet(farmId=farm_id, fleetId=fleet_id)
    try:
        deadline.get_fleet(farmId=farm_id, fleetId=fleet_id)
        raise AssertionError("expected ResourceNotFoundException reading the deleted fleet")
    except ClientError as exc:
        error = exc.response.get("Error", {})
        assert error.get("Code") == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException, got {error}"
        )
        expected_message = f"Resource of type fleet with id {fleet_id} does not exist."
        assert error.get("Message") == expected_message, (
            f"expected message {expected_message!r}, got {error.get('Message')!r}"
        )

    try:
        deadline.update_fleet(farmId=farm_id, fleetId=fleet_id, displayName="sim2real-dead-fleet-update")
        raise AssertionError("expected ResourceNotFoundException updating the deleted fleet")
    except ClientError as exc:
        error = exc.response.get("Error", {})
        assert error.get("Code") == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException, got {error}"
        )
        expected_message = f"Resource of type fleet with id {fleet_id} does not exist."
        assert error.get("Message") == expected_message, (
            f"expected message {expected_message!r}, got {error.get('Message')!r}"
        )


# ===== helpers =====
def _create_farm_with_retry(ctx, deadline):
    from botocore.exceptions import ClientError

    last_exc = None
    deadline_t = time.monotonic() + 180.0
    while time.monotonic() < deadline_t:
        try:
            return deadline.create_farm(displayName=ctx.unique_name("sim2real-farm-"))["farmId"]
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
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
