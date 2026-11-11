"""concurrent-add-role-to-instance-duplicate-race."""
from __future__ import annotations

import json
import secrets
import string
import threading
import time

from botocore.exceptions import ClientError
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-add-role-to-instance-duplicate-race"
GROUP = "concurrency"
SERVICES = ["rds"]

_FEATURE = "s3Export"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two simultaneous AddRoleToDBInstance calls for one RoleArn/FeatureName associate it once: one
    succeeds, and the other, like a later sequential duplicate, is refused with InvalidParameterValue
    or DBInstanceRoleAlreadyExists and the exact message."""
    rds = ctx.client("rds")
    iam = ctx.client("iam")

    engine_version = _pick_s3export_engine_version(rds)
    if engine_version is None:
        raise AssertionError("no postgres engine version in this region advertises the s3Export feature")

    instance_id = ctx.unique_name("sim2real-rolerace-")
    password = _rand_password()
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="postgres",
        EngineVersion=engine_version,
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": "true"}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    )
    _wait_instance_status(ctx, instance_id, "available", timeout_s=1200)

    role_name = ctx.unique_name("sim2real-rolerace-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "rds.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    _wait_role_association_ready(ctx, rds, instance_id, role_arn)

    def _add():
        rds.add_role_to_db_instance(
            DBInstanceIdentifier=instance_id, RoleArn=role_arn, FeatureName=_FEATURE
        )
        return role_arn

    ctx.on_cleanup(lambda: _remove_role_ignore_missing(rds, instance_id, role_arn))

    result_a, result_b = _race_two_with_state_retry(_add, _add)
    outcomes = [result_a, result_b]
    successes = [r for r in outcomes if r["ok"]]
    failures = [r for r in outcomes if not r["ok"]]
    assert len(successes) == 1, f"expected exactly 1 success, got {len(successes)}: {outcomes!r}"
    assert len(failures) == 1, f"expected exactly 1 failure, got {len(failures)}: {outcomes!r}"
    refusals = {
        (
            "InvalidParameterValue",
            f"The engine PostgreSQL supports only one ARN associated with feature name {_FEATURE}.",
        ),
        (
            "DBInstanceRoleAlreadyExists",
            f"The {role_arn} IAM role or {_FEATURE} feature is already associated with the "
            f"{instance_id} DB instance. Check the name and try again.",
        ),
    }
    loser = (failures[0]["code"], failures[0]["message"])
    assert loser in refusals, f"unexpected loser refusal {loser!r} (expected one of {refusals})"

    final = _wait_role_count(ctx, instance_id, 1, timeout_s=120)
    assert final[0]["RoleArn"] == role_arn, f"expected surviving role {role_arn!r}, got {final!r}"

    _wait_instance_status(ctx, instance_id, "available", timeout_s=600)
    repeat = _attempt_with_state_retry(_add)
    assert (repeat["code"], repeat["message"]) in refusals, (
        f"expected a sequential duplicate refused with one of {refusals}, got {repeat!r}"
    )


def _wait_role_association_ready(ctx, rds, instance_id, role_arn, timeout_s=120, poll_s=5) -> None:
    """A just-created IAM role can lag AWS's cross-service consistency window: RDS rejects it with
    InvalidParameterValue until the role has propagated. Retry the real call -- not a sleep --
    until it either succeeds or the deadline passes, then undo it so the race that follows starts
    from a clean, unassociated instance."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.add_role_to_db_instance(
                DBInstanceIdentifier=instance_id, RoleArn=role_arn, FeatureName=_FEATURE
            )
            break
        except Exception as exc:
            response = getattr(exc, "response", None)
            code = response.get("Error", {}).get("Code") if response else None
            if code == "InvalidParameterValue" and time.monotonic() < deadline:
                time.sleep(poll_s)
                continue
            raise
    _wait_role_count(ctx, instance_id, 1, timeout_s=120)
    _wait_instance_status(ctx, instance_id, "available", timeout_s=600)
    _remove_role_with_state_retry(rds, instance_id, role_arn)
    _wait_role_count(ctx, instance_id, 0, timeout_s=120)
    _wait_instance_status(ctx, instance_id, "available", timeout_s=600)


def _remove_role_with_state_retry(rds, instance_id, role_arn, timeout_s=120, poll_s=5) -> None:
    """RemoveRoleFromDBInstance can itself reject with InvalidDBInstanceState even after
    DescribeDBInstances already reports "available" with no PendingModifiedValues -- the same
    settling lag _race_two_with_state_retry retries around for AddRoleToDBInstance."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.remove_role_from_db_instance(
                DBInstanceIdentifier=instance_id, RoleArn=role_arn, FeatureName=_FEATURE
            )
            return
        except Exception as exc:
            response = getattr(exc, "response", None)
            code = response.get("Error", {}).get("Code") if response else None
            if code == "InvalidDBInstanceState" and time.monotonic() < deadline:
                time.sleep(poll_s)
                continue
            raise


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _pick_s3export_engine_version(rds):
    versions = rds.describe_db_engine_versions(Engine="postgres")["DBEngineVersions"]
    supported = [
        v["EngineVersion"] for v in versions if "s3Export" in v.get("SupportedFeatureNames", [])
    ]
    return sorted(supported)[-1] if supported else None


def _remove_role_ignore_missing(rds, instance_id, role_arn, timeout_s=300, poll_s=10) -> None:
    """Teardown: retry while the instance is still settling the association, and tolerate an
    association or instance that is already gone."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.remove_role_from_db_instance(
                DBInstanceIdentifier=instance_id, RoleArn=role_arn, FeatureName=_FEATURE
            )
            return
        except rds.exceptions.DBInstanceRoleNotFoundFault:
            return
        except rds.exceptions.DBInstanceNotFoundFault:
            return
        except Exception as exc:
            response = getattr(exc, "response", None)
            code = response.get("Error", {}).get("Code") if response else None
            if code == "InvalidDBInstanceState" and time.monotonic() < deadline:
                time.sleep(poll_s)
                continue
            raise


def _attempt_with_state_retry(fn, retry_timeout_s=120) -> dict:
    """Call fn, retrying while the instance reports InvalidDBInstanceState, and return its outcome."""
    deadline = time.monotonic() + retry_timeout_s
    while True:
        try:
            return {"ok": True, "value": fn(), "code": None, "message": None}
        except ClientError as exc:
            error = exc.response.get("Error", {})
            if error.get("Code") == "InvalidDBInstanceState" and time.monotonic() < deadline:
                time.sleep(5)
                continue
            return {"ok": False, "value": None, "code": error.get("Code"), "message": error.get("Message")}


def _race_two_with_state_retry(fn_a, fn_b, retry_timeout_s=120) -> tuple[dict, dict]:
    """Fire fn_a/fn_b as close to simultaneously as possible via a barrier. Either call can
    transiently reject with InvalidDBInstanceState while the instance is mid-modification
    from the OTHER racer's in-flight AddRoleToDBInstance, even though the operation would
    otherwise resolve to the specific DBInstanceRoleAlreadyExists duplicate-role error --
    so each wrapped call retries on that specific transient code until it observes the
    real terminal outcome (success or the duplicate-role rejection), not a one-shot
    attempt that could spuriously report a state-conflict instead of a duplicate-role
    rejection."""
    barrier = threading.Barrier(2)

    def _wrap(fn):
        def _inner():
            barrier.wait()
            deadline = time.monotonic() + retry_timeout_s
            while True:
                try:
                    return {"ok": True, "value": fn(), "code": None, "message": None}
                except Exception as exc:  # noqa: BLE001 - classify below
                    response = getattr(exc, "response", None)
                    if response is None:
                        raise
                    code = response.get("Error", {}).get("Code")
                    if code == "InvalidDBInstanceState" and time.monotonic() < deadline:
                        time.sleep(5)
                        continue
                    message = response.get("Error", {}).get("Message")
                    return {"ok": False, "value": None, "code": code, "message": message}

        return _inner

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(_wrap(fn_a))
        fut_b = pool.submit(_wrap(fn_b))
        return fut_a.result(), fut_b.result()


def _wait_instance_status(ctx, instance_id, target_status, timeout_s=1200, poll_s=20) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if last["DBInstanceStatus"] == target_status and not last.get("PendingModifiedValues"):
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"instance {instance_id} never reached {target_status!r}, "
        f"last status {last and last['DBInstanceStatus']!r}"
    )


def _wait_role_count(ctx, instance_id, target_count, timeout_s=120, poll_s=10) -> list:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last: list = []
    while time.monotonic() < deadline:
        instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        last = instance.get("AssociatedRoles", [])
        if len(last) == target_count:
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"instance {instance_id} associated-role count never reached {target_count}, "
        f"last observed {len(last)}"
    )


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
