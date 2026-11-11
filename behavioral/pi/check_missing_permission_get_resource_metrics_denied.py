"""missing-permission-get-resource-metrics-denied."""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "missing-permission-get-resource-metrics-denied"
GROUP = "overly-permissive"
SERVICES = ["pi"]


@tags("axis:rejection", "cap:c2", "cap:c7", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """An IAM user with no policies gets AccessDeniedException with its exact message from
    GetResourceMetrics, while the same call with the caller's credentials returns one metric."""
    _require_pi_slow_checks(ctx)
    dbi = _create_pi_source(ctx)
    pi = ctx.client("pi")

    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-pi-nopower-")
    user_arn = iam.create_user(UserName=user_name)["User"]["Arn"]
    ctx.on_cleanup(lambda: _delete_user(iam, user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]

    now = datetime.now(timezone.utc)
    start = now - timedelta(minutes=30)

    unauthorized_pi = _wait_for_usable_credentials(
        ctx, key["AccessKeyId"], key["SecretAccessKey"]
    )

    code, message = _wait_for_denial(
        lambda: unauthorized_pi.get_resource_metrics(
            ServiceType="RDS",
            Identifier=dbi,
            MetricQueries=[{"Metric": "db.load.avg"}],
            StartTime=start,
            EndTime=now,
        )
    )
    assert code == "AccessDeniedException", (
        "expected a caller with zero IAM permissions to get IAM's implicit-deny "
        f"(AccessDeniedException), got {code!r}"
    )
    expected_message = (
        f"User: {user_arn} is not authorized to perform: pi:GetResourceMetrics on resource: "
        f"{dbi} because no identity-based policy allows the pi:GetResourceMetrics action"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # positive control: the normally-privileged test credentials still succeed
    resp = pi.get_resource_metrics(
        ServiceType="RDS",
        Identifier=dbi,
        MetricQueries=[{"Metric": "db.load.avg"}],
        StartTime=start,
        EndTime=now,
    )
    assert len(resp["MetricList"]) == 1


def _require_pi_slow_checks(ctx) -> None:
    """No-op: pi is a heavy-provisioning service, so it gets the long per-check budget, and each
    check creates its own PI-enabled RDS instance (see _create_pi_source)."""
    return


def _create_pi_source(ctx) -> str:
    """Create this check's own PI-enabled RDS instance in the run's shared network, register its
    teardown, and return its DbiResourceId once it is available.

    The report operations need Database Insights in advanced mode, not bare Performance
    Insights. The instance is private and nothing connects to it (the checks only call the pi
    API about it), so its own security group admits nothing; the group exists so the teardown
    can wait for the instance's network interfaces to detach. The admin password is random per
    run.
    """
    import secrets as _secrets
    import time as _time
    from botocore.exceptions import ClientError as _ClientError

    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")
    network = ctx.network()
    db_id = ctx.unique_name("sim2real-behav-pi-")
    subnet_group_name = f"{db_id}-subnets"
    tags = [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    ]
    sg_id = ec2.create_security_group(
        GroupName=f"{db_id}-sg",
        Description="sim2real pi check",
        VpcId=network.vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tags}],
    )["GroupId"]
    ctx.on_cleanup(lambda: _delete_pi_source(rds, ec2, db_id, subnet_group_name, sg_id))
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real pi check",
        SubnetIds=network.subnet_ids,
        Tags=tags,
    )
    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.medium",
        Engine="mysql",
        MasterUsername="piadmin",
        MasterUserPassword=_secrets.token_urlsafe(18),
        AllocatedStorage=20,
        EnablePerformanceInsights=True,
        DatabaseInsightsMode="advanced",
        PerformanceInsightsRetentionPeriod=465,
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        MultiAZ=False,
        StorageType="gp2",
        DBSubnetGroupName=subnet_group_name,
        VpcSecurityGroupIds=[sg_id],
        Tags=tags,
    )

    deadline = _time.monotonic() + 1200
    desc = {}
    while _time.monotonic() < deadline:
        try:
            desc = rds.describe_db_instances(DBInstanceIdentifier=db_id)["DBInstances"][0]
        except _ClientError as exc:
            if exc.response["Error"]["Code"] != "DBInstanceNotFound":
                raise
        status = desc.get("DBInstanceStatus")
        if status == "available":
            break
        if status in ("failed", "incompatible-parameters", "incompatible-network", "storage-full"):
            raise AssertionError(f"RDS instance {db_id} entered a bad state: {status}")
        _time.sleep(2)
    else:
        raise AssertionError(
            f"RDS instance {db_id} never became available (last status: {desc.get('DBInstanceStatus')})"
        )
    assert desc.get("DatabaseInsightsMode") == "advanced", (
        f"expected Database Insights advanced mode on {db_id}, got {desc.get('DatabaseInsightsMode')!r}"
    )
    return desc["DbiResourceId"]


def _delete_pi_source(rds, ec2, db_id, subnet_group_name, sg_id):
    """Delete the instance (no final snapshot), wait for its network interfaces to detach, then
    delete its subnet group and its security group, waiting for each delete. Every step runs even
    if an earlier one fails; then the teardown raises naming each step that failed. The waits sum
    to at most 870 s, so the runner's teardown timeout must allow at least 900 s.
    """
    import time as _time
    from botocore.exceptions import ClientError as _ClientError

    def _gone(delete, describe, gone_code, busy_codes, timeout_s):
        deadline = _time.monotonic() + timeout_s
        deleted = False
        while True:
            try:
                if not deleted:
                    delete()
                    deleted = True
                describe()
            except _ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == gone_code:
                    return
                if code not in busy_codes:
                    raise
            if _time.monotonic() >= deadline:
                raise TimeoutError(f"still present after {timeout_s}s")
            _time.sleep(15)

    def _enis_detached(timeout_s):
        deadline = _time.monotonic() + timeout_s
        while True:
            enis = ec2.describe_network_interfaces(
                Filters=[{"Name": "group-id", "Values": [sg_id]}]
            )["NetworkInterfaces"]
            if not enis:
                return
            if _time.monotonic() >= deadline:
                ids = [e["NetworkInterfaceId"] for e in enis]
                raise TimeoutError(f"{ids} still attached after {timeout_s}s")
            _time.sleep(15)

    # Wire codes as the rds model's awsQueryError traits give them: DBInstanceNotFound and
    # InvalidDBInstanceState drop "Fault"; DBSubnetGroupNotFoundFault and
    # InvalidDBSubnetGroupStateFault keep it.
    steps = [
        (f"instance {db_id}", lambda: _gone(
            lambda: rds.delete_db_instance(
                DBInstanceIdentifier=db_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
            ),
            lambda: rds.describe_db_instances(DBInstanceIdentifier=db_id),
            "DBInstanceNotFound", {"InvalidDBInstanceState"}, 600,
        )),
        (f"network interfaces in {sg_id}", lambda: _enis_detached(120)),
        (f"subnet group {subnet_group_name}", lambda: _gone(
            lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name),
            lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=subnet_group_name),
            "DBSubnetGroupNotFoundFault", {"InvalidDBSubnetGroupStateFault"}, 60,
        )),
        (f"security group {sg_id}", lambda: _gone(
            lambda: ec2.delete_security_group(GroupId=sg_id),
            lambda: ec2.describe_security_groups(GroupIds=[sg_id]),
            "InvalidGroup.NotFound", {"DependencyViolation"}, 90,
        )),
    ]
    failures = []
    for what, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - every step runs; each failure is raised below
            failures.append(f"{what}: {exc!r}")
    if failures:
        raise RuntimeError("pi teardown failed: " + "; ".join(failures))


def _delete_user(iam, user_name: str) -> None:
    try:
        for key in iam.list_access_keys(UserName=user_name)["AccessKeyMetadata"]:
            iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"])
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_user(UserName=user_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _wait_for_usable_credentials(ctx, access_key_id: str, secret_access_key: str, timeout_s: float = 60.0):
    """IAM credential propagation is eventually consistent; poll STS until the new keys work,
    then return a pi client built from them."""
    creds = {"aws_access_key_id": access_key_id, "aws_secret_access_key": secret_access_key}
    sts = ctx.client("sts", creds=creds)
    deadline = time.monotonic() + timeout_s
    last_error = None
    while time.monotonic() < deadline:
        try:
            sts.get_caller_identity()
            return ctx.client("pi", creds=creds)
        except Exception as err:  # noqa: BLE001
            last_error = err
            time.sleep(3)
    raise AssertionError(f"new IAM user credentials never became usable: {last_error}")


def _wait_for_denial(fn, timeout_s: float = 60.0):
    """Retry only the auth-layer-not-yet-propagated errors: a fresh IAM key can be accepted by
    STS's global get_caller_identity, then rejected by PI's regional endpoint with
    UnrecognizedClientException, then -- three seconds later, same key -- correctly denied with
    AccessDeniedException. That gap means _wait_for_usable_credentials' STS check alone is not
    sufficient proof the key is usable at PI's endpoint. Returns (code, message); any other
    outcome is final, and an unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            result = fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code in ("UnrecognizedClientException", "InvalidClientTokenId") and time.monotonic() < deadline:
                time.sleep(3)
                continue
            return code, err.response["Error"].get("Message")
        raise AssertionError(f"expected the call to be denied, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
