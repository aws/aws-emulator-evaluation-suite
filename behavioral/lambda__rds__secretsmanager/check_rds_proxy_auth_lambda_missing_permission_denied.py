"""rds-proxy-auth-lambda-missing-permission-denied."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
import secrets

CHECK = "rds-proxy-auth-lambda-missing-permission-denied"
GROUP = "permission-boundary"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:rejection", "cap:c4", "cap:c7", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A proxy whose role cannot read its Secrets Manager secret settles UNAVAILABLE/AUTH_FAILURE,
    while a twin with GetSecretValue reaches AVAILABLE; granting the permission recovers the target.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_TargetHealth.html
    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy.troubleshooting.html
    """
    rds = ctx.client("rds")
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")

    master_username = "admin"
    master_password = "Aa1!" + secrets.token_urlsafe(18)
    db_id = ctx.unique_name("sim2real-behav-dbi-")

    subnet_ids, sg_id = _vpc_prereqs(ctx)

    subnet_group = ctx.unique_name("sim2real-behav-dbsubnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=subnet_group,
        DBSubnetGroupDescription=CHECK,
        SubnetIds=subnet_ids,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _retry_while_held(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=subnet_group), "InvalidDBSubnetGroupStateFault", timeout_s=1200.0))

    rds.create_db_instance(
        DBInstanceIdentifier=db_id,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername=master_username,
        MasterUserPassword=master_password,
        AllocatedStorage=20,
        BackupRetentionPeriod=0,
        PubliclyAccessible=False,
        VpcSecurityGroupIds=[sg_id],
        DBSubnetGroupName=subnet_group,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=db_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
        )
    )

    secret = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-proxy-secret-"),
        SecretString=json.dumps({"username": master_username, "password": master_password}),
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    account_id = sts.get_caller_identity()["Account"]

    role_good_arn, _role_good_name = _create_proxy_role(ctx, secret_arn, account_id, grant_secret_access=True)
    role_bad_arn, role_bad_name = _create_proxy_role(ctx, secret_arn, account_id, grant_secret_access=False)

    proxy_good = ctx.unique_name("sim2real-behav-proxy-good-")
    proxy_bad = ctx.unique_name("sim2real-behav-proxy-bad-")
    _create_db_proxy(ctx, proxy_good, role_good_arn, secret_arn, subnet_ids, sg_id)
    _create_db_proxy(ctx, proxy_bad, role_bad_arn, secret_arn, subnet_ids, sg_id)

    _wait_for_db_instance_available(ctx, db_id, timeout_s=1200.0)
    _wait_for_proxy_available(ctx, proxy_good, timeout_s=900.0)
    _wait_for_proxy_available(ctx, proxy_bad, timeout_s=900.0)

    rds.register_db_proxy_targets(DBProxyName=proxy_good, DBInstanceIdentifiers=[db_id])
    rds.register_db_proxy_targets(DBProxyName=proxy_bad, DBInstanceIdentifiers=[db_id])

    # Positive control: the correctly-permissioned proxy authenticates successfully. Per
    # API_TargetHealth.html the lifecycle can bounce through UNAVAILABLE before settling on
    # AVAILABLE, so keep polling until AVAILABLE is actually observed rather than stopping on
    # the first UNAVAILABLE reading.
    good_target = _wait_for_target_available(ctx, proxy_good, db_id, timeout_s=600.0)
    assert good_target["TargetHealth"]["State"] == "AVAILABLE"

    # Negative: the proxy whose role cannot read the secret must never authenticate. Poll until it
    # reports UNAVAILABLE/AUTH_FAILURE, failing on any AVAILABLE reading, then hold briefly to show
    # the failure is settled, and assert the state and reason.
    bad_target = _confirm_target_never_available(ctx, proxy_bad, db_id, timeout_s=600.0)
    assert bad_target["TargetHealth"]["State"] == "UNAVAILABLE"
    assert bad_target["TargetHealth"]["Reason"] == "AUTH_FAILURE"

    # Restore: this is a policy denying access, not an input that can never become valid, so the
    # denial must be shown reversible on the SAME target -- otherwise "denied" is indistinguishable
    # from "this proxy could never have worked."
    iam = ctx.client("iam")
    restore_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}
        ],
    }
    iam.put_role_policy(
        RoleName=role_bad_name,
        PolicyName="proxy-secret-access",
        PolicyDocument=json.dumps(restore_policy),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_bad_name, PolicyName="proxy-secret-access")
    )
    restored_target = _wait_for_target_available(ctx, proxy_bad, db_id, timeout_s=600.0)
    assert restored_target["TargetHealth"]["State"] == "AVAILABLE", (
        f"granting secretsmanager:GetSecretValue to {role_bad_name} must let the SAME proxy "
        f"target recover to AVAILABLE, got {restored_target['TargetHealth']}"
    )


def _vpc_prereqs(ctx: Any) -> tuple[list[str], str]:
    """Adopt the default VPC when it spans 2+ AZs; otherwise create a throwaway VPC of our own.
    A freshly provisioned account may have no default VPC at all, and RDS Proxy's own
    cross-AZ requirement means a default VPC confined to one AZ is unusable too -- either way
    this check provisions what it needs instead of failing on an environment assumption."""
    ec2 = ctx.client("ec2")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict[str, str] = {}
        for subnet in subnets:
            by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
        if len(by_az) >= 2:
            sgs = ec2.describe_security_groups(
                Filters=[
                    {"Name": "vpc-id", "Values": [vpc_id]},
                    {"Name": "group-name", "Values": ["default"]},
                ]
            )["SecurityGroups"]
            if sgs:
                return list(by_az.values())[:3], sgs[0]["GroupId"]

    azs = [
        az["ZoneName"]
        for az in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}, {"Name": "zone-name", "Values": ctx.network().availability_zones}]
        )["AvailabilityZones"][:2]
    ]
    if len(azs) < 2:
        raise AssertionError(f"region {ctx.region} does not have 2+ available AZs for RDS Proxy")

    vpc_id = ec2.create_vpc(CidrBlock="10.198.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "sim2real-check", "Value": CHECK}])

    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id, CidrBlock=f"10.198.{i}.0/24", AvailabilityZone=az
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)

    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError(f"freshly created VPC {vpc_id} has no default security group")
    return subnet_ids, sgs[0]["GroupId"]


def _create_proxy_role(
    ctx: Any, secret_arn: str, account_id: str, *, grant_secret_access: bool
) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-proxy-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "rds.amazonaws.com"},
                "Action": "sts:AssumeRole",
                "Condition": {"StringEquals": {"aws:SourceAccount": account_id}},
            }
        ],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    if grant_secret_access:
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}
            ],
        }
        iam.put_role_policy(
            RoleName=role_name, PolicyName="proxy-secret-access", PolicyDocument=json.dumps(policy_doc)
        )
        ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="proxy-secret-access"))
    # else: deliberately no secretsmanager permissions attached at all -- GetSecretValue is
    # implicitly denied for this role.
    return role_arn, role_name


def _create_db_proxy(
    ctx: Any, proxy_name: str, role_arn: str, secret_arn: str, subnet_ids: list[str], sg_id: str
) -> None:
    """create_db_proxy retried against IAM role-propagation lag (bounded poll, not a sleep)."""
    from botocore.exceptions import ClientError

    rds = ctx.client("rds")
    deadline = time.monotonic() + 60.0
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            rds.create_db_proxy(
                DBProxyName=proxy_name,
                EngineFamily="MYSQL",
                Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret_arn, "IAMAuth": "DISABLED"}],
                RoleArn=role_arn,
                VpcSubnetIds=subnet_ids,
                VpcSecurityGroupIds=[sg_id],
                RequireTLS=False,
            )
            ctx.on_cleanup(lambda: rds.delete_db_proxy(DBProxyName=proxy_name))
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("InvalidParameterValue", "InvalidParameterValueException"):
                raise
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"create_db_proxy({proxy_name}) never succeeded (role propagation?): {last_err}")


def _wait_for_db_instance_available(ctx: Any, db_id: str, timeout_s: float = 1200.0) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_status = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=db_id)
        instance = resp["DBInstances"][0]
        last_status = instance["DBInstanceStatus"]
        if last_status == "available":
            return instance
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"DB instance {db_id} to become available: the run budget ended first; not graded")
    raise AssertionError(f"DB instance {db_id} never became available (last status={last_status})")


def _wait_for_proxy_available(ctx: Any, proxy_name: str, timeout_s: float = 900.0) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_status = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_proxies(DBProxyName=proxy_name)
        proxy = resp["DBProxies"][0]
        last_status = proxy["Status"]
        if last_status == "available":
            return proxy
        if last_status in ("incompatible-network", "insufficient-resource-limits"):
            raise AssertionError(f"DB proxy {proxy_name} entered unrecoverable status {last_status}")
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"DB proxy {proxy_name} to become available: the run budget ended first; not graded")
    raise AssertionError(f"DB proxy {proxy_name} never became available (last status={last_status})")


def _wait_for_target_state(
    ctx: Any, proxy_name: str, db_id: str, terminal_states: set[str], timeout_s: float = 600.0
) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_target = None
    while time.monotonic() < deadline:
        targets = rds.describe_db_proxy_targets(DBProxyName=proxy_name)["Targets"]
        for target in targets:
            if target.get("RdsResourceId") == db_id:
                last_target = target
                if target["TargetHealth"]["State"] in terminal_states:
                    return target
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"target for {db_id} on proxy {proxy_name} to reach {terminal_states}: the run budget ended first; not graded")
    raise AssertionError(
        f"target for {db_id} on proxy {proxy_name} never reached {terminal_states} "
        f"(last observed={last_target})"
    )


def _wait_for_target_available(ctx: Any, proxy_name: str, db_id: str, timeout_s: float = 600.0) -> dict:
    """Poll until the target settles on AVAILABLE (ignoring transient UNAVAILABLE readings
    that precede it, per the documented registering -> unavailable -> available lifecycle)."""
    return _wait_for_target_state(ctx, proxy_name, db_id, {"AVAILABLE"}, timeout_s=timeout_s)


# How long the target must stay UNAVAILABLE/AUTH_FAILURE once it first reports it.
_SETTLE_S = 8.0


def _confirm_target_never_available(ctx: Any, proxy_name: str, db_id: str, timeout_s: float = 600.0) -> dict:
    """Poll until the target reports UNAVAILABLE/AUTH_FAILURE, then hold for _SETTLE_S. Fails loudly
    if the target ever reports AVAILABLE (the negative-control assumption would be broken); returns
    the last observed target once the hold elapses."""
    rds = ctx.client("rds")
    deadline = time.monotonic() + _budget_s(ctx, timeout_s)
    last_target = None
    settle_until = None
    while True:
        targets = rds.describe_db_proxy_targets(DBProxyName=proxy_name)["Targets"]
        for target in targets:
            if target.get("RdsResourceId") == db_id:
                last_target = target
                health = target["TargetHealth"]
                if health["State"] == "AVAILABLE":
                    raise AssertionError(
                        f"target for {db_id} on proxy {proxy_name} became AVAILABLE despite "
                        "its role lacking secretsmanager:GetSecretValue"
                    )
                if (
                    settle_until is None
                    and health["State"] == "UNAVAILABLE"
                    and health.get("Reason") == "AUTH_FAILURE"
                ):
                    settle_until = time.monotonic() + _SETTLE_S
        now = time.monotonic()
        if settle_until is not None and now >= settle_until:
            return last_target
        if settle_until is None and now >= deadline:
            break
        time.sleep(2)
    if _budget_spent(ctx):
        raise TimeoutError(f"target for {db_id} on proxy {proxy_name} to report UNAVAILABLE/AUTH_FAILURE: the run budget ended first; not graded")
    if last_target is None:
        raise AssertionError(f"target for {db_id} on proxy {proxy_name} was never observed")
    raise AssertionError(
        f"target for {db_id} on proxy {proxy_name} never reported UNAVAILABLE/AUTH_FAILURE "
        f"(last observed={last_target})"
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


# A resource in this VPC deletes asynchronously: its ENIs linger in the subnet / security group, so
# an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails with DependencyViolation. Wait
# (bounded) for the ENIs to go, retry DependencyViolation in the same window, then raise naming the
# ENIs still attached. The window is shared by all of one check's network deletes.
_NET_TEARDOWN_S = 1260.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(2)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(2)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


def _retry_while_held(fn, *codes, timeout_s=600.0, interval_s=15.0):
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
