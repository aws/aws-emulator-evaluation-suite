"""missing-iam-permission-access-denied-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "missing-iam-permission-access-denied-rejected"
GROUP = "overly-permissive"
SERVICES = ["rds-data"]


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """A new IAM identity with no permissions gets AccessDeniedException from ExecuteStatement
    (implicit deny), while permitted credentials succeed on the same resource and statement."""
    db = _provision_cluster(ctx)
    iam = ctx.client("iam")
    user_name = ctx.unique_name("sim2real-rdsdata-nouser-")
    user_arn = iam.create_user(UserName=user_name, Tags=[{"Key": "sim2real", "Value": CHECK}])["User"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_user(UserName=user_name))
    key = iam.create_access_key(UserName=user_name)["AccessKey"]
    ctx.on_cleanup(lambda: iam.delete_access_key(UserName=user_name, AccessKeyId=key["AccessKeyId"]))

    base = ctx.client("rds-data")
    denied = ctx.client(
        "rds-data",
        creds={
            "aws_access_key_id": key["AccessKeyId"],
            "aws_secret_access_key": key["SecretAccessKey"],
        },
    )

    def _attempt():
        denied.execute_statement(resourceArn=db["resourceArn"], secretArn=db["secretArn"], sql="SELECT 1")

    # New IAM credentials can take a few seconds to propagate; retry until the
    # expected AccessDeniedException (rather than a transient signing error)
    # is observed, or the bound is exhausted.
    deadline = time.monotonic() + 90
    error = {}
    while time.monotonic() < deadline:
        error = _refusal(_attempt)
        if error.get("Code") == "AccessDeniedException":
            break
        time.sleep(5)
    assert error.get("Code") == "AccessDeniedException", (
        f"a brand-new IAM identity with no attached permissions must get AccessDeniedException "
        f"calling rds-data:ExecuteStatement; got {error!r}"
    )
    assert error.get("Message") == (
        f"User: {user_arn} is not authorized to perform: rds-data:ExecuteStatement on resource: "
        f"{db['resourceArn']} because no identity-based policy allows the rds-data:ExecuteStatement action"
    ), f"unexpected refusal message: {error.get('Message')!r}"

    # Positive control: permitted credentials make the identical call and read the value back,
    # so the denial is about the identity, not the resource, statement or cluster.
    resp = base.execute_statement(resourceArn=db["resourceArn"], secretArn=db["secretArn"], sql="SELECT 1")
    value = resp["records"][0][0]["longValue"]
    assert value == 1, f"expected the permitted identity's SELECT 1 to return 1, got {value!r}"


# rds-data's data plane IS the AWS API (ExecuteStatement/BatchExecuteStatement/...) — there's no
# separate native-protocol round-trip to gate behind an opt-in flag, so nothing connects to the
# cluster and its security group admits nothing. Each check creates its own Aurora Serverless v2
# cluster and writer in the run's shared network (~10 min) and tears them down; the admin
# password is managed by RDS in Secrets Manager, so the check never handles one.


def _refusal(fn):
    """The botocore Error dict (Code, Message) fn() raised; an unexpected success raises."""
    try:
        resp = fn()
    except ClientError as err:
        return err.response.get("Error", {})
    raise AssertionError(f"the call was ACCEPTED and returned {resp!r}")


def _wait_until(probe, predicate, timeout_s=900, interval_s=10):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never met, last observed: {last}")


def _wait_data_api_ready(ctx, resource_arn, secret_arn, timeout_s=300):
    rdsdata = ctx.client("rds-data")
    deadline = time.monotonic() + timeout_s
    last_code = None
    while time.monotonic() < deadline:
        try:
            rdsdata.execute_statement(resourceArn=resource_arn, secretArn=secret_arn, sql="SELECT 1")
            return
        except ClientError as err:
            last_code = err.response["Error"]["Code"]
            if last_code in (
                "DatabaseResumingException",
                "HttpEndpointNotEnabledException",
                "DatabaseNotFoundException",
                "ServiceUnavailableError",
                "DatabaseUnavailableException",
            ):
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"Data API never became ready (last error: {last_code})")


def _create_clusters(ctx, http_endpoint_flags):
    """Create one Aurora Serverless v2 cluster and writer per EnableHttpEndpoint flag, without
    waiting, so clusters provision concurrently. The security group admits nothing (the Data API
    is an AWS API); it exists so teardown can wait for the writers' network interfaces to detach."""
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")
    network = ctx.network()
    base = ctx.unique_name("sim2real-behav-rdsdata-")
    subnet_group_name = f"{base}-subnets"
    tags = [
        {"Key": "sim2real:managed", "Value": "true"},
        {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
    ]
    sg_id = ec2.create_security_group(
        GroupName=f"{base}-sg",
        Description="sim2real rds-data check",
        VpcId=network.vpc_id,
        TagSpecifications=[{"ResourceType": "security-group", "Tags": tags}],
    )["GroupId"]
    dbs = []
    ctx.on_cleanup(lambda: _delete_clusters(rds, ec2, dbs, subnet_group_name, sg_id))
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real rds-data check",
        SubnetIds=network.subnet_ids,
        Tags=tags,
    )
    for n, enable_http_endpoint in enumerate(http_endpoint_flags):
        cluster_id = f"{base}-c{n}"
        db = {"clusterId": cluster_id, "instanceId": f"{cluster_id}-i", "database": "simparitydb"}
        dbs.append(db)
        db["resourceArn"] = rds.create_db_cluster(
            DBClusterIdentifier=cluster_id,
            Engine="aurora-mysql",
            DatabaseName="simparitydb",
            MasterUsername="simparity",
            ManageMasterUserPassword=True,
            EnableHttpEndpoint=enable_http_endpoint,
            ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 2.0},
            StorageEncrypted=True,
            DeletionProtection=False,
            DBSubnetGroupName=subnet_group_name,
            VpcSecurityGroupIds=[sg_id],
            Tags=tags,
        )["DBCluster"]["DBClusterArn"]
        rds.create_db_instance(
            DBInstanceIdentifier=db["instanceId"],
            DBClusterIdentifier=cluster_id,
            Engine="aurora-mysql",
            DBInstanceClass="db.serverless",
            Tags=tags,
        )
    return dbs


def _await_cluster(ctx, db):
    """Wait until a cluster from _create_clusters and its writer are available (and, with the
    HTTP endpoint on, until the Data API answers), then return its handle with the secret ARN."""
    rds = ctx.client("rds")
    _wait_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=db["instanceId"])["DBInstances"][0]["DBInstanceStatus"],
        lambda status: status == "available",
        timeout_s=1200,
    )
    cluster = _wait_until(
        lambda: rds.describe_db_clusters(DBClusterIdentifier=db["clusterId"])["DBClusters"][0],
        lambda c: c["Status"] == "available" and "MasterUserSecret" in c,
        timeout_s=600,
    )
    db["secretArn"] = cluster["MasterUserSecret"]["SecretArn"]
    if cluster.get("HttpEndpointEnabled"):
        _wait_data_api_ready(ctx, db["resourceArn"], db["secretArn"])
    return db


def _provision_cluster(ctx, enable_http_endpoint=True):
    """Create this check's own Aurora Serverless v2 cluster and wait until it is usable."""
    return _await_cluster(ctx, _create_clusters(ctx, [enable_http_endpoint])[0])


def _delete_clusters(rds, ec2, dbs, subnet_group_name, sg_id):
    """Delete the writers, clusters, subnet group and security group, waiting for each step.
    Every step runs even if an earlier one fails; the teardown then raises naming each failure.
    The waits sum to at most 1740 s, inside the suite's 1800 s teardown budget."""
    def _gone(resources, gone_code, busy_codes, timeout_s):
        deadline = time.monotonic() + timeout_s
        pending = {i: False for i in range(len(resources))}
        while True:
            for i, accepted in list(pending.items()):
                delete, describe = resources[i]
                try:
                    if not accepted:
                        delete()
                        pending[i] = True
                    describe()
                except ClientError as exc:
                    code = exc.response["Error"]["Code"]
                    if code == gone_code:
                        del pending[i]
                        continue
                    if code not in busy_codes:
                        raise
            if not pending:
                return
            if time.monotonic() >= deadline:
                raise TimeoutError(f"{len(pending)} still present after {timeout_s}s")
            time.sleep(15)

    def _enis_detached(timeout_s):
        deadline = time.monotonic() + timeout_s
        while True:
            enis = ec2.describe_network_interfaces(
                Filters=[{"Name": "group-id", "Values": [sg_id]}]
            )["NetworkInterfaces"]
            if not enis:
                return
            if time.monotonic() >= deadline:
                ids = [e["NetworkInterfaceId"] for e in enis]
                raise TimeoutError(f"{ids} still attached after {timeout_s}s")
            time.sleep(15)

    def _instance(db):
        return (
            lambda: rds.delete_db_instance(DBInstanceIdentifier=db["instanceId"], SkipFinalSnapshot=True),
            lambda: rds.describe_db_instances(DBInstanceIdentifier=db["instanceId"]),
        )

    def _cluster(db):
        return (
            lambda: rds.delete_db_cluster(DBClusterIdentifier=db["clusterId"], SkipFinalSnapshot=True),
            lambda: rds.describe_db_clusters(DBClusterIdentifier=db["clusterId"]),
        )

    # Wire codes as the rds model's awsQueryError traits give them: DBInstanceNotFound and
    # InvalidDBInstanceState drop "Fault"; DBClusterNotFoundFault, InvalidDBClusterStateFault,
    # DBSubnetGroupNotFoundFault and InvalidDBSubnetGroupStateFault keep it.
    steps = [
        ("writers", lambda: _gone(
            [_instance(db) for db in dbs], "DBInstanceNotFound", {"InvalidDBInstanceState"}, 900,
        )),
        ("clusters", lambda: _gone(
            [_cluster(db) for db in dbs], "DBClusterNotFoundFault", {"InvalidDBClusterStateFault"}, 450,
        )),
        (f"network interfaces in {sg_id}", lambda: _enis_detached(180)),
        (f"subnet group {subnet_group_name}", lambda: _gone(
            [(
                lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name),
                lambda: rds.describe_db_subnet_groups(DBSubnetGroupName=subnet_group_name),
            )],
            "DBSubnetGroupNotFoundFault", {"InvalidDBSubnetGroupStateFault"}, 90,
        )),
        (f"security group {sg_id}", lambda: _gone(
            [(
                lambda: ec2.delete_security_group(GroupId=sg_id),
                lambda: ec2.describe_security_groups(GroupIds=[sg_id]),
            )],
            "InvalidGroup.NotFound", {"DependencyViolation"}, 120,
        )),
    ]
    failures = []
    for what, step in steps:
        try:
            step()
        except Exception as exc:  # noqa: BLE001 - every step runs; each failure is raised below
            failures.append(f"{what} of {[db['clusterId'] for db in dbs]}: {exc!r}")
    if failures:
        raise RuntimeError(f"rds-data teardown failed: {'; '.join(failures)}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
