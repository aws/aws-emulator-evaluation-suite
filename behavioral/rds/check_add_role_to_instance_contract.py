"""add-role-to-instance-contract."""
from __future__ import annotations

import json
import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "add-role-to-instance-contract"
GROUP = 'errors'
SERVICES = ['rds']

ERR_DB_INSTANCE_NOT_FOUND = "DBInstanceNotFound"
_FEATURE = "s3Import"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AddRoleToDBInstance accepts a real instance and role (positive control), rejects a
    nonexistent instance with DBInstanceNotFound, and rejects a malformed RoleArn with
    InvalidParameterValue even against the same real instance."""
    rds = ctx.client("rds")
    iam = ctx.client("iam")
    account = ctx.client("sts").get_caller_identity()["Account"]

    # Role before instance: CreateDBInstance's multi-minute wait covers IAM propagation.
    role_arn = _create_role(ctx, iam)

    engine_version = _pick_s3import_engine_version(rds)
    if engine_version is None:
        raise AssertionError("no postgres engine version in this region advertises the s3Import feature")

    instance_id = ctx.unique_name("sim2real-instrolecontract-")
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
    ctx.on_cleanup(lambda: _delete_instance_ignore_missing(rds, instance_id))
    _wait_instance_status(rds, instance_id, "available", timeout_s=1200)

    # Positive control: a real instance plus a real, well-formed role must be accepted --
    # without this, the two rejections below cannot be told apart from "rejects everything".
    _add_role_with_retry(rds, instance_id, role_arn, _FEATURE)
    ctx.on_cleanup(lambda: _remove_role_ignore_missing(rds, instance_id, role_arn))
    _wait_role_count(rds, instance_id, 1, timeout_s=600)

    bogus_id = ctx.unique_name("sim2real-behav-inst-missing-")
    code, message = _error_detail(
        lambda: rds.add_role_to_db_instance(
            DBInstanceIdentifier=bogus_id,
            RoleArn=f"arn:aws:iam::{account}:role/does-not-exist",
            FeatureName=_FEATURE,
        )
    )
    assert code == ERR_DB_INSTANCE_NOT_FOUND, f"unexpected error code: {code!r}"
    expected = f"DBInstance not found: {bogus_id}"
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    # Malformed RoleArn against the SAME real instance: parameter validation fires
    # independently of the instance lookup.
    code2, message2 = _error_detail(
        lambda: rds.add_role_to_db_instance(
            DBInstanceIdentifier=instance_id,
            RoleArn="not-a-valid-role-arn",
            FeatureName=_FEATURE,
        )
    )
    assert code2 == "InvalidParameterValue", f"unexpected error code: {code2!r}"
    expected2 = "Invalid Role ARN: not-a-valid-role-arn"
    assert message2 == expected2, f"unexpected message: {message2!r} (expected {expected2!r})"

    # Effect absent: the rejected malformed-ARN call must not have touched the real association.
    inst = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    associated = inst.get("AssociatedRoles", [])
    assert len(associated) == 1, f"expected exactly 1 association, got {associated!r}"
    assert associated[0]["RoleArn"] == role_arn, (
        f"expected the surviving association to be {role_arn!r}, got {associated[0]['RoleArn']!r}"
    )


def _error_detail(fn):
    try:
        fn()
    except ClientError as e:
        error = e.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError("the call succeeded; expected a rejection")


def _pick_s3import_engine_version(rds):
    versions = rds.describe_db_engine_versions(Engine="postgres")["DBEngineVersions"]
    supported = [
        v["EngineVersion"] for v in versions if "s3Import" in v.get("SupportedFeatureNames", [])
    ]
    return sorted(supported)[-1] if supported else None


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _create_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-instrolecontract-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return arn


def _add_role_with_retry(rds, instance_id, role_arn, feature_name, timeout_s=300, poll_s=15) -> None:
    """AddRoleToDBInstance transiently rejects with InvalidDBInstanceState while the instance is
    still settling right after CreateDBInstance reports "available"; bounded-retry, not one shot."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            rds.add_role_to_db_instance(
                DBInstanceIdentifier=instance_id, RoleArn=role_arn, FeatureName=feature_name
            )
            return
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidDBInstanceState":
                raise
            last_exc = exc
            time.sleep(poll_s)
    raise AssertionError(f"AddRoleToDBInstance never became valid within {timeout_s}s: {last_exc}")


def _remove_role_ignore_missing(rds, instance_id, role_arn, timeout_s=600, poll_s=15) -> None:
    """RemoveRoleFromDBInstance, retrying InvalidDBInstanceState while the association settles;
    the instance teardown drops any association left behind."""
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
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidDBInstanceState":
                raise
            if time.monotonic() >= deadline:
                return
            time.sleep(poll_s)


def _delete_instance_ignore_missing(rds, instance_id) -> None:
    try:
        rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    except ClientError as e:
        if e.response.get("Error", {}).get("Code") != "DBInstanceNotFound":
            raise


def _wait_instance_status(rds, instance_id, target_status, timeout_s=1200, poll_s=20) -> dict:
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


def _wait_role_count(rds, instance_id, target_count, timeout_s=120, poll_s=10) -> list:
    deadline = time.monotonic() + timeout_s
    last: list = []
    while time.monotonic() < deadline:
        instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        last = instance.get("AssociatedRoles", [])
        settled = instance["DBInstanceStatus"] == "available" and all(
            r.get("Status") == "ACTIVE" for r in last
        )
        if len(last) == target_count and settled:
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
