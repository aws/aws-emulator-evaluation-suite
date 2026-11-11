"""add-role-to-instance-quota-exceeded-rejected."""
from __future__ import annotations

import json
import secrets
import string
import time

from botocore.exceptions import ClientError

import botocore.exceptions

from behavioral_harness import tags

CHECK = "add-role-to-instance-quota-exceeded-rejected"
GROUP = "error-semantics"
SERVICES = ["rds"]

_FEATURE = "s3Import"


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-adding a role already associated under the same FeatureName is rejected (for postgres
    s3Import: InvalidParameterValue, not DBInstanceRoleAlreadyExistsFault) with no duplicate
    association; removing then re-adding the role succeeds."""
    rds = ctx.client("rds")
    iam = ctx.client("iam")

    bucket = _create_bucket(ctx)
    instance_id = ctx.unique_name("sim2real-instrolequota-")
    password = _rand_password()
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        Engine="postgres",
        DBInstanceClass="db.t3.micro",
        AllocatedStorage=20,
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        PubliclyAccessible=False,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    )
    _wait_instance_status(ctx, instance_id, "available", timeout_s=1200)

    role_arn = _create_role(ctx, iam, "role-0", bucket)

    _add_role_with_retry(ctx, rds, instance_id, role_arn)
    ctx.on_cleanup(lambda: _remove_role_ignore_missing(rds, instance_id, role_arn))
    # DBInstanceStatus can read "available" while the just-added role association is still
    # PENDING; probing the duplicate-add rejection before it reaches ACTIVE gets
    # InvalidDBInstanceState instead of the settled-association rejection asserted below.
    _wait_role_active(ctx, instance_id, role_arn, timeout_s=300)

    code, message = _error_detail(
        lambda: rds.add_role_to_db_instance(
            DBInstanceIdentifier=instance_id, RoleArn=role_arn, FeatureName=_FEATURE
        )
    )
    # engine=postgres rejects a same-ARN/same-FeatureName resubmission with
    # InvalidParameterValue, not the documented DBInstanceRoleAlreadyExistsFault.
    assert code == "InvalidParameterValue", f"unexpected error code {code!r}: {message!r}"
    expected = "The engine PostgreSQL supports only one ARN associated with feature name s3Import."
    assert message == expected, f"unexpected message: {message!r} (expected {expected!r})"

    # Effect absent: still exactly one association, not duplicated.
    instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
    associated = instance.get("AssociatedRoles", [])
    assert len(associated) == 1, f"expected exactly 1 associated role after rejected duplicate, got {associated!r}"

    # Positive control (same file): removing then re-adding the SAME role succeeds -- the
    # rejection was about the existing association, not a broken instance or role.
    rds.remove_role_from_db_instance(
        DBInstanceIdentifier=instance_id, RoleArn=role_arn, FeatureName=_FEATURE
    )
    _wait_role_count(ctx, instance_id, 0, timeout_s=120)
    _wait_instance_status(ctx, instance_id, "available", timeout_s=600)
    _add_role_with_retry(ctx, rds, instance_id, role_arn)
    final = _wait_role_active(ctx, instance_id, role_arn, timeout_s=300)
    assert final["RoleArn"] == role_arn, f"expected re-added role {role_arn!r}, got {final!r}"


def _error_detail(fn):
    try:
        fn()
    except Exception as exc:  # noqa: BLE001 - classify below
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError("the call succeeded; expected a rejection")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-instrolequota-")
    kwargs = {}
    if ctx.region != "us-east-1":
        # S3 rejects an explicit LocationConstraint for us-east-1 specifically; every other
        # region requires one. Not a region pin on this check -- an S3 CreateBucket quirk.
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=name, **kwargs)

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _create_role(ctx, iam, suffix: str, bucket: str) -> str:
    # AddRoleToDBInstance rejects a role that only has a trust policy (InvalidParameterValue,
    # AWS_ROLE_INTEGRATION); it validates the role grants s3Import-usable S3 permissions.
    role_name = ctx.unique_name(f"sim2real-instrolequota-{suffix}-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = f"{role_name}-s3import"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Action": ["s3:GetObject", "s3:ListBucket"],
            "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
        }],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return arn


def _remove_role_ignore_missing(rds, instance_id, role_arn) -> None:
    try:
        rds.remove_role_from_db_instance(
            DBInstanceIdentifier=instance_id, RoleArn=role_arn, FeatureName=_FEATURE
        )
    except rds.exceptions.DBInstanceRoleNotFoundFault:
        pass
    except rds.exceptions.DBInstanceNotFoundFault:
        pass


def _add_role_with_retry(ctx, rds, instance_id, role_arn, timeout_s=300, poll_s=2) -> None:
    """AddRoleToDBInstance, retrying InvalidDBInstanceState while a prior role change settles and
    InvalidParameterValue (AWS_ROLE_INTEGRATION) while the fresh inline policy propagates."""
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            rds.add_role_to_db_instance(
                DBInstanceIdentifier=instance_id, RoleArn=role_arn, FeatureName=_FEATURE
            )
            return
        except botocore.exceptions.ClientError as exc:
            error = exc.response.get("Error", {})
            code = error.get("Code")
            message = error.get("Message", "")
            retryable = code == "InvalidDBInstanceState" or (
                code == "InvalidParameterValue" and "AWS_ROLE_INTEGRATION" in message
            )
            if not retryable:
                raise
            last_exc = exc
            time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError("AddRoleToDBInstance role propagation: the run budget ended first; not graded")
    raise AssertionError(f"AddRoleToDBInstance never became valid within {timeout_s}s: {last_exc}")


def _wait_instance_status(ctx, instance_id, target_status, timeout_s=1200, poll_s=2) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        if last["DBInstanceStatus"] == target_status and not last.get("PendingModifiedValues"):
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"instance {instance_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"instance {instance_id} never reached {target_status!r} with no pending modifications, "
        f"last status {last and last['DBInstanceStatus']!r}, "
        f"pending {last and last.get('PendingModifiedValues')!r}"
    )


def _wait_role_active(ctx, instance_id, role_arn, timeout_s=300, poll_s=2) -> dict:
    """Wait until the instance is "available" AND the named role's own association Status is
    "ACTIVE" -- a role can already appear in AssociatedRoles as PENDING while the instance
    itself reads "available"."""
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_instance_status = None
    last_role_status = None
    while time.monotonic() < deadline:
        instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        last_instance_status = instance["DBInstanceStatus"]
        match = next((r for r in instance.get("AssociatedRoles", []) if r["RoleArn"] == role_arn), None)
        last_role_status = match and match["Status"]
        if last_instance_status == "available" and match is not None and match["Status"] == "ACTIVE":
            return match
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"role {role_arn} on instance {instance_id} ACTIVE: the run budget ended first; not graded")
    raise AssertionError(
        f"role {role_arn} on instance {instance_id} never reached ACTIVE within {timeout_s}s, "
        f"last instance status {last_instance_status!r}, last role status {last_role_status!r}"
    )


def _wait_role_count(ctx, instance_id, target_count, timeout_s=120, poll_s=2) -> list:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last: list = []
    while time.monotonic() < deadline:
        instance = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
        last = instance.get("AssociatedRoles", [])
        if len(last) == target_count:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(
            f"instance {instance_id} associated-role count {target_count}: the run budget ended first; not graded"
        )
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


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=2.0):
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
