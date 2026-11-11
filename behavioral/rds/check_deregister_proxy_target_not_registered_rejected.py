"""deregister-proxy-target-not-registered-rejected."""
from __future__ import annotations

import json
import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deregister-proxy-target-not-registered-rejected"
GROUP = "error-semantics"
SERVICES = ["rds"]

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-degtarget-"},
]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeregisterDBProxyTargets for a DB cluster that is real (exists) but was never registered
    as a target of the given proxy's target group fails with DBProxyTargetNotFoundFault -- and
    the identical deregister call succeeds once the SAME cluster IS first registered."""
    ec2 = ctx.client("ec2")
    subnet_ids = _default_vpc_subnets(ec2, ctx=ctx)
    if subnet_ids is None:
        raise AssertionError("no VPC with subnets in 2+ AZs found in this account/region")

    rds = ctx.client("rds")
    iam = ctx.client("iam")
    secretsmanager = ctx.client("secretsmanager")

    secret_arn = _create_secret(ctx, secretsmanager)
    role_arn = _create_proxy_role(ctx, iam, secret_arn)

    proxy_name = ctx.unique_name("sim2real-degtarget-")
    _create_db_proxy_with_retry(
        rds,
        ctx=ctx,
        timeout_s=_budget_s(ctx, 90),
        DBProxyName=proxy_name,
        EngineFamily="POSTGRESQL",
        Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret_arn, "IAMAuth": "DISABLED"}],
        RoleArn=role_arn,
        VpcSubnetIds=subnet_ids,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_proxy(DBProxyName=proxy_name))
    _wait_proxy_status(ctx, proxy_name, "available", timeout_s=900)

    cluster_id = ctx.unique_name("sim2real-degtargetcl-")
    password = _rand_password()
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-postgresql",
        MasterUsername="s2radmin",
        MasterUserPassword=password,
        ServerlessV2ScalingConfiguration={"MinCapacity": 0.5, "MaxCapacity": 1},
        DeletionProtection=False,
        Tags=_MANAGED_TAGS,
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    )
    _wait_cluster_status(ctx, cluster_id, "available", timeout_s=900)

    code, msg = _client_error(
        lambda: rds.deregister_db_proxy_targets(
            DBProxyName=proxy_name, TargetGroupName="default", DBClusterIdentifiers=[cluster_id]
        )
    )
    assert code == "DBProxyTargetNotFoundFault", f"unexpected error code {code!r}"
    assert msg == "Missing targets", msg

    # Effect absent: the target group has no targets at all (nothing to have removed).
    targets = rds.describe_db_proxy_targets(DBProxyName=proxy_name, TargetGroupName="default")[
        "Targets"
    ]
    assert targets == [], f"expected no targets registered yet, got {targets!r}"

    # Positive control (same file): register the cluster, THEN the identical deregister call
    # succeeds -- pinning that the rejection was specifically about registration state.
    rds.register_db_proxy_targets(DBProxyName=proxy_name, DBClusterIdentifiers=[cluster_id])
    registered = _wait_target_count(ctx, proxy_name, 1, timeout_s=120)
    assert registered[0]["RdsResourceId"] == cluster_id or registered[0]["TrackedClusterId"] == cluster_id, (
        f"expected registered target to reference cluster {cluster_id!r}, got {registered[0]!r}"
    )

    rds.deregister_db_proxy_targets(
        DBProxyName=proxy_name, TargetGroupName="default", DBClusterIdentifiers=[cluster_id]
    )
    _wait_target_count(ctx, proxy_name, 0, timeout_s=120)


def _client_error(fn):
    """Return the (code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded: {result!r}")


def _rand_password() -> str:
    alphabet = string.ascii_letters + string.digits
    return "Aa1" + "".join(secrets.choice(alphabet) for _ in range(16))


def _default_vpc_subnets(ec2, *, ctx) -> list[str] | None:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        return None
    return list(by_az.values())[:3]


def _create_secret(ctx, secretsmanager) -> str:
    name = ctx.unique_name("sim2real-degtargetsecret-")
    secret = secretsmanager.create_secret(
        Name=name,
        SecretString=json.dumps({"username": "s2radmin", "password": "Sim2real-placeholder-1"}),
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
    )
    return secret["ARN"]


def _create_proxy_role(ctx, iam, secret_arn: str) -> str:
    role_name = ctx.unique_name("sim2real-degtargetrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_MANAGED_TAGS
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-degtarget-secret-access", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-degtarget-secret-access")
    )
    return arn


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _create_db_proxy_with_retry(rds, *, ctx, timeout_s=90, poll_s=2, **kwargs) -> None:
    """CreateDBProxy can reject the freshly-created role while its trust policy is
    still propagating to the RDS service; retry until it settles or the deadline passes."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.create_db_proxy(**kwargs)
            return
        except ClientError as exc:
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError("CreateDBProxy role propagation: the run budget ended first; not graded") from exc
                raise
            time.sleep(poll_s)


def _wait_proxy_status(ctx, proxy_name, target_status, timeout_s=900, poll_s=2) -> dict:
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


def _wait_target_count(ctx, proxy_name, target_count, timeout_s=120, poll_s=2) -> list:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last: list = []
    while time.monotonic() < deadline:
        last = rds.describe_db_proxy_targets(DBProxyName=proxy_name, TargetGroupName="default")[
            "Targets"
        ]
        if len(last) == target_count:
            return last
        time.sleep(poll_s)
    if _budget_spent(ctx):
        raise TimeoutError(f"proxy {proxy_name} target count {target_count}: the run budget ended first; not graded")
    raise AssertionError(
        f"proxy {proxy_name} target count never reached {target_count}, last observed {len(last)}"
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
