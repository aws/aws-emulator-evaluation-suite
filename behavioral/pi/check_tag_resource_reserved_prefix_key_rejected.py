"""tag-resource-reserved-prefix-key-rejected."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "tag-resource-reserved-prefix-key-rejected"
GROUP = "overly-permissive"
SERVICES = ["pi"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource with an "aws:" tag key on a well-formed nonexistent analysis-report ARN gets
    NotAuthorizedException with its exact message, while a ResourceARN outside the pi pattern gets
    ValidationException with its exact message."""
    _require_pi_slow_checks(ctx)
    dbi = _create_pi_source(ctx)
    pi = ctx.client("pi")
    arn = _synthetic_report_arn(ctx, dbi)

    # positive control: the pi wiring itself is healthy for this dbi -- without this, a target that
    # denies every pi call (broken creds, broken wiring) would score identically to one that
    # correctly enforces resource-level authorization on the two negatives below. PI's metric
    # catalog registration can lag DB availability by a couple minutes, so this bounded-polls rather
    # than asserting on the very first response.
    import time as _time

    deadline = _time.monotonic() + 180.0
    metrics: list = []
    while _time.monotonic() < deadline:
        metrics = pi.list_available_resource_metrics(
            ServiceType="RDS", Identifier=dbi, MetricTypes=["db"]
        )["Metrics"]
        if metrics:
            break
        _time.sleep(2)
    assert metrics, "expected the real PI-enabled instance to report at least one available metric"

    code, message = _error(
        lambda: pi.tag_resource(
            ServiceType="RDS", ResourceARN=arn, Tags=[{"Key": "aws:reserved", "Value": "x"}]
        )
    )
    assert code == "NotAuthorizedException", (
        f"expected TagResource against a nonexistent (but well-formed) report ARN to be denied "
        f"at the authorization stage, got {code!r}"
    )
    expected_message = "The specified resource is not authorized for this account"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # distinct boundary: a ResourceARN that doesn't match the pi ARN pattern at all fails one
    # step EARLIER, at generic shape validation -- before authorization is ever evaluated
    code2, message2 = _error(
        lambda: pi.tag_resource(
            ServiceType="RDS", ResourceARN="not-an-arn-at-all", Tags=[{"Key": "ok", "Value": "x"}]
        )
    )
    assert code2 == "ValidationException", (
        f"expected a malformed (non-pi-pattern) ResourceARN to fail shape validation, got {code2!r}"
    )
    expected_message2 = "Validation error(s) detected: Value at 'resourceARN' failed to satisfy constraints."
    assert message2 == expected_message2, f"expected message {expected_message2!r}, got {message2!r}"


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


def _synthetic_report_arn(ctx, dbi: str) -> str:
    """A syntactically-valid (matches perf-reports/{service}/{dbi}/{report-id}) but never-issued
    report ARN -- sufficient to exercise TagResource's INPUT validation, which runs
    independently of report existence."""
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bogus_report_id = "report-00000000000000000"
    return f"arn:aws:pi:{ctx.region}:{account_id}:perf-reports/rds/{dbi}/{bogus_report_id}"


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises,
    because a target accepting what AWS refuses must not read as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
