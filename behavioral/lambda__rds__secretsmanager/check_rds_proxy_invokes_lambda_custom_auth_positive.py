"""rds-proxy-invokes-lambda-custom-auth-positive."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "rds-proxy-invokes-lambda-custom-auth-positive"
GROUP = "resource-binding"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An RDS Proxy with AuthScheme=SECRETS resolves its configured Secrets Manager secret and
    authenticates to the target DB: the proxy target reaches AVAILABLE health, not merely a 200
    from CreateDBProxy (RDS Proxy offers no Lambda custom-auth scheme)."""
    rds = ctx.client("rds")
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")

    master_username = "admin"
    master_password = "ProxyTestPassw0rd123"
    db_id = ctx.unique_name("sim2real-behav-dbi-")

    vpc_id, subnet_ids, sg_id = _default_vpc_prereqs(ctx)

    subnet_group = _network_db_subnet_group(ctx, rds)
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(
        lambda: rds.delete_db_instance(
            DBInstanceIdentifier=db_id, SkipFinalSnapshot=True, DeleteAutomatedBackups=True
        )
    )

    secret = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-proxy-secret-"),
        SecretString=json.dumps({"username": master_username, "password": master_password}),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    account_id = sts.get_caller_identity()["Account"]
    role_arn = _create_proxy_role(ctx, [secret_arn], account_id)

    proxy_name = ctx.unique_name("sim2real-behav-proxy-")
    _create_db_proxy(
        ctx,
        proxy_name=proxy_name,
        role_arn=role_arn,
        secret_arn=secret_arn,
        subnet_ids=subnet_ids,
        sg_id=sg_id,
    )

    _wait_for_db_instance_available(ctx, db_id, timeout_s=1200.0)
    _wait_for_proxy_available(ctx, proxy_name, timeout_s=900.0)

    rds.register_db_proxy_targets(DBProxyName=proxy_name, DBInstanceIdentifiers=[db_id])

    target = _wait_for_target_state(ctx, proxy_name, db_id, {"AVAILABLE"}, timeout_s=600.0)
    assert target["TargetHealth"]["State"] == "AVAILABLE", (
        f"expected the registered target to reach AVAILABLE health once the proxy "
        f"authenticated to it via the resolved secret, got {target!r}"
    )

    # Independent read of the proxy's own Auth binding, at the same destination the target
    # health came from: the resolved binding is the SECRETS scheme we configured -- and
    # nothing Lambda-shaped -- confirming AVAILABLE health came from that binding, not from
    # some other credential path.
    proxies = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"]
    assert len(proxies) == 1, f"expected exactly one proxy named {proxy_name!r}, got {proxies!r}"
    auth_entries = proxies[0]["Auth"]
    assert len(auth_entries) == 1, f"expected exactly one Auth entry, got {auth_entries!r}"
    auth = auth_entries[0]
    assert auth.get("AuthScheme") == "SECRETS", f"expected AuthScheme=SECRETS, got {auth!r}"
    assert auth.get("SecretArn") == secret_arn, f"expected the configured secret ARN, got {auth!r}"
    assert not any(
        "lambda" in str(key).lower() or "arn:aws:lambda" in str(value).lower()
        for key, value in auth.items()
    ), f"unexpected Lambda-shaped field in a real RDS Proxy Auth entry: {auth!r}"


# ===== helpers =====


def _default_vpc_prereqs(ctx: Any) -> tuple[str, list[str], str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available in this account/region to host the DB proxy")
    vpc_id = vpcs[0]["VpcId"]

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for subnet in subnets:
        by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not span 2+ availability zones required by RDS Proxy")
    subnet_ids = list(by_az.values())[:3]

    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    sg_id = sgs[0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _create_proxy_role(ctx: Any, secret_arns: list[str], account_id: str) -> str:
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
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arns}
        ],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName="proxy-secret-access", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="proxy-secret-access"))
    return role_arn


def _create_db_proxy(
    ctx: Any, *, proxy_name: str, role_arn: str, secret_arn: str, subnet_ids: list[str], sg_id: str
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
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
            ctx.on_cleanup(lambda: rds.delete_db_proxy(DBProxyName=proxy_name))
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("InvalidParameterValue", "InvalidParameterValueException"):
                raise
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"create_db_proxy never succeeded (role propagation?): {last_err}")


def _wait_for_db_instance_available(ctx: Any, db_id: str, timeout_s: float = 1200.0) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + min(timeout_s, max(1.0, (ctx.time_left() or timeout_s) - 5.0))
    last_status = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_instances(DBInstanceIdentifier=db_id)
        instance = resp["DBInstances"][0]
        last_status = instance["DBInstanceStatus"]
        if last_status == "available":
            return instance
        time.sleep(2)
    raise AssertionError(f"DB instance {db_id} never became available (last status={last_status})")


def _wait_for_proxy_available(ctx: Any, proxy_name: str, timeout_s: float = 900.0) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + min(timeout_s, max(1.0, (ctx.time_left() or timeout_s) - 5.0))
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
    raise AssertionError(f"DB proxy {proxy_name} never became available (last status={last_status})")


def _wait_for_target_state(
    ctx: Any, proxy_name: str, db_id: str, terminal_states: set[str], timeout_s: float = 600.0
) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + min(timeout_s, max(1.0, (ctx.time_left() or timeout_s) - 5.0))
    last_target = None
    while time.monotonic() < deadline:
        targets = rds.describe_db_proxy_targets(DBProxyName=proxy_name)["Targets"]
        for target in targets:
            if target.get("RdsResourceId") == db_id:
                last_target = target
                if target["TargetHealth"]["State"] in terminal_states:
                    return target
        time.sleep(2)
    raise AssertionError(
        f"target for {db_id} on proxy {proxy_name} never reached {terminal_states} "
        f"(last observed={last_target})"
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
