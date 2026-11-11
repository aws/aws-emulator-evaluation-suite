"""fleet-min-worker-count-exceeds-max-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "fleet-min-worker-count-exceeds-max-rejected"
GROUP = "overly-permissive"
SERVICES = ["deadline"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFleet rejects minWorkerCount > maxWorkerCount with ValidationException and
    creates no fleet, while the same request with a valid ordering succeeds."""
    deadline = ctx.client("deadline")

    farm_id = _create_farm_with_retry(ctx, deadline)
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_farm(farmId=farm_id)))

    role_arn = _create_fleet_trust_role(ctx, farm_id)
    rejected_name = ctx.unique_name("sim2real-fleet-rejected-")

    # Break exactly one thing: minWorkerCount (5) greater than maxWorkerCount (2). The freshly
    # created role's trust policy may not have propagated yet, so retry the transient
    # AccessDeniedException/AssumeRole failures that causes rather than sleeping unconditionally
    # before the first attempt.
    error = _client_error_with_retry(
        lambda: deadline.create_fleet(
            farmId=farm_id,
            displayName=rejected_name,
            roleArn=role_arn,
            minWorkerCount=5,
            maxWorkerCount=2,
            configuration=_customer_managed_fleet_configuration(),
            tags={"sim2real": CHECK},
        )
    )
    assert error.get("Code") == "ValidationException", f"expected ValidationException, got {error}"
    expected_message = "minWorkerCount (5) must be less than or equal to maxWorkerCount (2)"
    assert error.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {error.get('Message')!r}"
    )

    # Effect absent: no fleet with that display name exists.
    names = [f["displayName"] for f in deadline.list_fleets(farmId=farm_id)["fleets"]]
    assert rejected_name not in names, "rejected fleet was created anyway"

    # Positive control: the same request with a valid ordering succeeds.
    accepted_name = ctx.unique_name("sim2real-fleet-accepted-")
    fleet_id = _create_fleet_with_retry(
        ctx,
        deadline,
        farmId=farm_id,
        displayName=accepted_name,
        roleArn=role_arn,
        minWorkerCount=0,
        maxWorkerCount=2,
        configuration=_customer_managed_fleet_configuration(),
        tags={"sim2real": CHECK},
    )
    ctx.on_cleanup(lambda: _safe(lambda: deadline.delete_fleet(farmId=farm_id, fleetId=fleet_id)))
    fleet = deadline.get_fleet(farmId=farm_id, fleetId=fleet_id)
    assert fleet["displayName"] == accepted_name, (
        f"expected accepted fleet displayName {accepted_name!r}, got {fleet['displayName']!r}"
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


def _client_error_with_retry(fn) -> dict:
    """Call fn(); return its botocore Error dict. Retries only the transient
    AccessDeniedException/AssumeRole failures caused by IAM role-propagation lag, bounded to
    60s. An unexpected SUCCESS raises rather than returning a falsy sentinel, because an
    over-permissive target accepting a call real AWS refuses must not be reported as a plain
    code mismatch."""
    from botocore.exceptions import ClientError

    last_exc = None
    deadline_t = time.monotonic() + 60.0
    while time.monotonic() < deadline_t:
        try:
            result = fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            msg = str(exc)
            if code == "AccessDeniedException" or "AssumeRole" in msg:
                last_exc = exc
                time.sleep(2)
                continue
            return exc.response.get("Error", {})
        else:
            raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED: {result!r}")
    raise last_exc


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
    # IAM role + policy attachment propagation lag is handled by the bounded retries in
    # _client_error_with_retry and _create_fleet_with_retry below, not by an unconditional wait here.
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
