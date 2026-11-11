"""describe-db-proxy-targets-registration-order-preserved."""
from __future__ import annotations

import json
import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-db-proxy-targets-registration-order-preserved"
GROUP = "ordering"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBProxyTargets lists an Aurora cluster's writer and reader targets in the same order
    on every repeated call."""
    vpc = _default_vpc_and_subnets(ctx)
    if vpc is None:
        raise AssertionError("no shared network VPC with >=2 subnets available to host the proxy")

    rds = ctx.client("rds")
    iam = ctx.client("iam")
    sm = ctx.client("secretsmanager")
    password = _rand_password()

    cluster_id = ctx.unique_name("sim2real-proxyord-cluster-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        DeletionProtection=False,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )

    instance_ids = [ctx.unique_name(f"sim2real-proxyord-{i}-") for i in range(2)]
    for instance_id in instance_ids:
        rds.create_db_instance(
            DBInstanceIdentifier=instance_id,
            Engine="aurora-mysql",
            DBInstanceClass="db.t3.medium",
            DBClusterIdentifier=cluster_id,
        )
        ctx.on_cleanup(
            lambda iid=instance_id: rds.delete_db_instance(
                DBInstanceIdentifier=iid, SkipFinalSnapshot=True
            )
        )

    secret_arn = sm.create_secret(
        Name=ctx.unique_name("sim2real-proxyord-secret-"),
        SecretString=json.dumps({"username": "s2radmin", "password": password}),
    )["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    role_name = ctx.unique_name("sim2real-proxyord-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"], "Resource": secret_arn}
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="secrets-access", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="secrets-access"))

    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=900)
    _wait_instances_status(ctx, instance_ids, "available", timeout_s=1200)

    proxy_name = ctx.unique_name("sim2real-proxyord-")
    _create_proxy_with_retry(
        rds,
        ctx=ctx,
        timeout_s=_budget_s(ctx, 90.0),
        DBProxyName=proxy_name,
        EngineFamily="MYSQL",
        RoleArn=role_arn,
        VpcSubnetIds=vpc["subnet_ids"],
        VpcSecurityGroupIds=[vpc["sg_id"]],
        Auth=[{"AuthScheme": "SECRETS", "IAMAuth": "DISABLED", "SecretArn": secret_arn}],
        RequireTLS=False,
    )
    ctx.on_cleanup(lambda: rds.delete_db_proxy(DBProxyName=proxy_name))
    _wait_proxy_status(ctx, proxy_name, "available", timeout_s=900)

    # A second instance target fails DBProxyTargetAlreadyRegisteredFault, so multiple targets
    # need a cluster: RDS discovers each member (writer + reader) as its own target.
    rds.register_db_proxy_targets(DBProxyName=proxy_name, DBClusterIdentifiers=[cluster_id])

    targets = _wait_all_targets_present(ctx, proxy_name, instance_ids, timeout_s=180)
    observed_order = [t["RdsResourceId"] for t in targets]
    assert set(instance_ids) <= set(observed_order), (
        f"observed targets {observed_order!r} do not include cluster members {instance_ids!r}"
    )

    # Stable across repeated calls -- exact same order every time.
    for _ in range(3):
        targets_again = rds.describe_db_proxy_targets(DBProxyName=proxy_name)["Targets"]
        observed_order_again = [t["RdsResourceId"] for t in targets_again]
        assert observed_order_again == observed_order, (
            f"target order changed across repeated calls: {observed_order!r} vs {observed_order_again!r}"
        )


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_proxy_with_retry(rds, *, ctx, timeout_s: float = 90.0, interval_s: float = 2.0, **kwargs) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.create_db_proxy(**kwargs)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValue" and time.monotonic() < deadline:
                time.sleep(interval_s)  # IAM role/policy propagation lag before RDS can assume it.
                continue
            if e.response["Error"]["Code"] == "InvalidParameterValue" and _budget_spent(ctx):
                raise TimeoutError("CreateDBProxy role propagation: the run budget ended first; not graded") from e
            raise


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _default_vpc_and_subnets(ctx) -> dict | None:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    az_to_subnet: dict[str, str] = {}
    for s in subnets:
        az_to_subnet.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(az_to_subnet) < 2:
        return None
    subnet_ids = list(az_to_subnet.values())[:3]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        return None
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "sg_id": sgs[0]["GroupId"]}


def _wait_cluster_status(ctx, cluster_id, target_status, timeout_s=900, poll_s=2) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"cluster {cluster_id} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"cluster {cluster_id} never reached {target_status!r}, last status {last and last['Status']!r}"
    )


def _wait_instances_status(ctx, instance_ids, target_status, timeout_s=1200, poll_s=2) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    pending = list(instance_ids)
    last: dict = {}
    while time.monotonic() < deadline:
        for instance_id in list(pending):
            inst = rds.describe_db_instances(DBInstanceIdentifier=instance_id)["DBInstances"][0]
            last[instance_id] = inst["DBInstanceStatus"]
            if inst["DBInstanceStatus"] == target_status and not inst.get("PendingModifiedValues"):
                pending.remove(instance_id)
        if not pending:
            return
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"instance(s) {pending!r} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"instance(s) {pending!r} never reached {target_status!r}, "
        f"last status {[last.get(i) for i in pending]!r}"
    )


def _wait_proxy_status(ctx, proxy_name, target_status, timeout_s=300, poll_s=2) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"proxy {proxy_name} {target_status!r}: the run budget ended first; not graded")
    raise AssertionError(
        f"proxy {proxy_name} never reached {target_status!r}, last status {last and last['Status']!r}"
    )


def _wait_all_targets_present(ctx, proxy_name, instance_ids, timeout_s=180, poll_s=2):
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last = []
    while time.monotonic() < deadline:
        last = rds.describe_db_proxy_targets(DBProxyName=proxy_name)["Targets"]
        observed = {t["RdsResourceId"] for t in last}
        if set(instance_ids) <= observed:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"proxy {proxy_name} listing all targets: the run budget ended first; not graded")
    raise AssertionError(
        f"proxy {proxy_name} never listed all {len(instance_ids)} targets, "
        f"last observed {[t.get('RdsResourceId') for t in last]!r}"
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

