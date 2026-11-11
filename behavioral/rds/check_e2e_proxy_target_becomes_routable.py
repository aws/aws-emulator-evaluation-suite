"""e2e-proxy-target-becomes-routable."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError, WaiterError

CHECK = "e2e-proxy-target-becomes-routable"
GROUP = "e2e"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Registering a running RDS instance as a DBProxy target drives its connection health to
    AVAILABLE, not just a 200 with the target stuck REGISTERING/UNAVAILABLE; re-registering
    the same target adds no second entry and leaves its health AVAILABLE."""
    rds = ctx.client("rds")
    iam = ctx.client("iam")
    secretsmanager = ctx.client("secretsmanager")

    _vpc_id, az_subnets = _pick_azs_with_subnets(ctx, count=2)
    subnet_ids = [s["SubnetId"] for s in az_subnets]

    subnet_group_name = ctx.unique_name("sim2real-rdspx-sng-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group_name,
        DBSubnetGroupDescription="sim2real proxy-target behavioral test",
        SubnetIds=subnet_ids,
    )
    ctx.on_cleanup(lambda: _retry_while_held(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group_name), "InvalidDBSubnetGroupStateFault", timeout_s=1200.0))

    instance_id = ctx.unique_name("sim2real-rdspx-db-")
    user = "s2radmin"
    password = _master_password()
    rds.create_db_instance(
        DBInstanceIdentifier=instance_id,
        DBInstanceClass="db.t3.micro",
        Engine="postgres",
        AllocatedStorage=20,
        StorageType="gp2",
        MasterUsername=user,
        MasterUserPassword=password,
        DBSubnetGroupName=subnet_group_name,
        PubliclyAccessible=False,
        BackupRetentionPeriod=1,
    )

    # Fire-and-forget: DeleteDBInstance takes minutes, far past the 60s cleanup budget;
    # AWS finishes the deletion after this process exits.
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(DBInstanceIdentifier=instance_id, SkipFinalSnapshot=True)
    )

    secret_name = ctx.unique_name("sim2real-rdspx-secret-")
    secret_arn = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"username": user, "password": password}),
    )["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    )

    role_name = ctx.unique_name("sim2real-rdspx-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"},
                        "Action": "sts:AssumeRole"}],
    }
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]["Arn"]
    policy_name = "sim2real-rdspx-secret-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps({
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow",
                 "Action": ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"],
                 "Resource": secret_arn},
                {"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "*",
                 "Condition": {"StringEquals": {"kms:ViaService":
                               f"secretsmanager.{ctx.region}.amazonaws.com"}}},
            ],
        }),
    )

    def _cleanup_role() -> None:
        iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)

    proxy_name = ctx.unique_name("sim2real-rdspx-proxy-")
    # IAM role trust propagation to the RDS control plane can lag by tens of seconds; retry the
    # bounded window rather than a fixed sleep before the one real attempt.
    deadline = time.monotonic() + _budget_s(ctx, 90)
    while True:
        try:
            rds.create_db_proxy(
                DBProxyName=proxy_name,
                EngineFamily="POSTGRESQL",
                Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret_arn, "IAMAuth": "DISABLED"}],
                RoleArn=role_arn,
                VpcSubnetIds=subnet_ids,
                RequireTLS=False,
            )
            break
        except Exception:
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(f"DBProxy {proxy_name!r} creation: the run budget ended first; not graded") from None
                raise
            time.sleep(2)

    def _cleanup_proxy() -> None:
        # Fire-and-forget: cleanups run LIFO on one thread within a single 60s budget, so a
        # poll here would starve every cleanup queued behind it.
        try:
            rds.deregister_db_proxy_targets(
                DBProxyName=proxy_name, DBInstanceIdentifiers=[instance_id]
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in (
                "DBClusterNotFoundFault",
                "DBInstanceNotFound",
                "DBProxyNotFoundFault",
                "DBProxyTargetGroupNotFoundFault",
                "DBProxyTargetNotFoundFault",
            ):
                raise
        rds.delete_db_proxy(DBProxyName=proxy_name)

    ctx.on_cleanup(_cleanup_proxy)

    # DBProxy creation can take several minutes; the target needs an available proxy.
    deadline = time.monotonic() + _budget_s(ctx, 900)
    while True:
        proxy = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]
        if proxy["Status"] == "available":
            break
        if proxy["Status"] in ("incompatible-network", "insufficient-resource-limits"):
            raise AssertionError(
                f"DBProxy {proxy_name!r} entered terminal failure status {proxy['Status']!r}"
            )
        if time.monotonic() >= deadline:
            if _budget_spent(ctx):
                raise TimeoutError(f"DBProxy {proxy_name!r} available: the run budget ended first; not graded")
            raise AssertionError(f"DBProxy {proxy_name!r} never reached available, status "
                                  f"stuck at {proxy['Status']!r}")
        time.sleep(2)


    # The RDS instance must be available before it can be registered as a routable target.
    try:
        rds.get_waiter("db_instance_available").wait(
            DBInstanceIdentifier=instance_id,
            WaiterConfig={"Delay": 2, "MaxAttempts": max(1, int(_budget_s(ctx, 1800) // 2))},
        )
    except WaiterError as exc:
        if "Max attempts exceeded" in str(exc) and _budget_spent(ctx):
            raise TimeoutError(f"instance {instance_id} available: the run budget ended first; not graded") from exc
        raise

    rds.register_db_proxy_targets(DBProxyName=proxy_name, DBInstanceIdentifiers=[instance_id])

    # Target health must actually reach AVAILABLE (registering -> unavailable -> available),
    # not just RegisterDBProxyTargets accepting the call.
    deadline = time.monotonic() + _budget_s(ctx, 600)
    last_state = None
    last_reason = None
    became_available = False
    while time.monotonic() < deadline:
        targets = rds.describe_db_proxy_targets(DBProxyName=proxy_name)["Targets"]
        matches = [t for t in targets if t.get("RdsResourceId") == instance_id]
        assert matches, f"registered target {instance_id!r} missing from DescribeDBProxyTargets"
        health = matches[0]["TargetHealth"]
        last_state = health.get("State")
        last_reason = health.get("Reason")
        if last_state == "AVAILABLE":
            became_available = True
            break
        time.sleep(2)
    if not became_available:
        if _budget_spent(ctx):
            raise TimeoutError(f"DBProxy target {instance_id!r} AVAILABLE: the run budget ended first; not graded")
        raise AssertionError(
            f"DBProxy target {instance_id!r} never reached AVAILABLE health, last state "
            f"{last_state!r} (reason={last_reason!r})"
        )


    # Re-registering the already-associated target must not duplicate it or disturb its health.
    _assert_duplicate_registration_idempotent(rds, proxy_name, instance_id)


def _assert_duplicate_registration_idempotent(rds, proxy_name: str, instance_id: str) -> None:
    rds.register_db_proxy_targets(DBProxyName=proxy_name, DBInstanceIdentifiers=[instance_id])
    targets = rds.describe_db_proxy_targets(DBProxyName=proxy_name)["Targets"]
    matches = [t for t in targets if t.get("RdsResourceId") == instance_id]
    assert len(matches) == 1, (
        f"re-registering already-registered target {instance_id!r} against {proxy_name!r} "
        f"produced {len(matches)} DescribeDBProxyTargets entries, expected exactly 1 (no duplicate)"
    )
    state = matches[0]["TargetHealth"]["State"]
    assert state == "AVAILABLE", (
        f"re-registering already-registered target {instance_id!r} against {proxy_name!r} "
        f"disturbed its health, now {state!r} (expected AVAILABLE unchanged)"
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


def _master_password() -> str:
    import secrets
    import string

    alphabet = string.ascii_letters + string.digits
    return "Sim2Real1" + "".join(secrets.choice(alphabet) for _ in range(12))


def _pick_azs_with_subnets(ctx, count: int = 2) -> tuple[str, list[dict]]:
    """Return (vpc_id, [subnet, ...]) covering `count` distinct AZs, for a DBSubnetGroup."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, dict] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s)
    if len(by_az) < count:
        raise AssertionError(
            f"VPC {vpc_id} has subnets in only {len(by_az)} AZ(s); need >= {count} for an RDS "
            f"subnet group / DB proxy"
        )
    return vpc_id, list(by_az.values())[:count]


def _retry_while_held(fn, *codes, timeout_s=600.0, interval_s=2.0):
    """Run a teardown delete, retrying while AWS refuses it because a dependent resource deleted just
    before it is still going away; after the deadline the last refusal is raised."""
    import time as _time

    from botocore.exceptions import ClientError

    deadline = _time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in codes or _time.monotonic() >= deadline:
                raise
        _time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
