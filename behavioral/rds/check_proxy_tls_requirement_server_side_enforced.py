"""proxy-tls-requirement-server-side-enforced."""
from __future__ import annotations

import json
import secrets
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "proxy-tls-requirement-server-side-enforced"
GROUP = "server-side"
SERVICES = ["rds"]


# tls-subject: the check asserts the proxy's server-side TLS requirement.
@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DBProxy created with RequireTLS=true still reports it after a target-group modification;
    only an explicit ModifyDBProxy on RequireTLS changes it."""
    vpc = _default_vpc_and_subnets(ctx)
    if vpc is None:
        raise AssertionError("no shared network VPC with >=2 subnets available to host the proxy")

    rds = ctx.client("rds")
    iam = ctx.client("iam")
    sm = ctx.client("secretsmanager")

    # A fresh account may never have needed AWSServiceRoleForRDS before: RDS itself (not our
    # per-proxy role) assumes this service-linked role to manage the proxy's ENIs, and
    # CreateDBProxy fails with InvalidParameterValue until it exists. Create-or-adopt, never
    # delete -- it is an account-level singleton other checks may also depend on.
    try:
        iam.create_service_linked_role(AWSServiceName="rds.amazonaws.com")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidInput":
            raise

    secret_arn = sm.create_secret(
        Name=ctx.unique_name("sim2real-proxytls-secret-"),
        SecretString=json.dumps({"username": "s2radmin", "password": _rand_password()}),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True))

    role_name = ctx.unique_name("sim2real-proxytls-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
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

    proxy_name = ctx.unique_name("sim2real-proxytls-")
    _create_db_proxy_with_retry(
        rds,
        proxy_name=proxy_name,
        role_arn=role_arn,
        secret_arn=secret_arn,
        subnet_ids=vpc["subnet_ids"],
        sg_id=vpc["sg_id"],
        timeout_s=90,
    )
    ctx.on_cleanup(lambda: rds.delete_db_proxy(DBProxyName=proxy_name))
    proxy = _wait_proxy_status(ctx, proxy_name, "available", timeout_s=300)
    assert proxy["RequireTLS"] is True, (
        f"proxy created with RequireTLS=True should read back True, got {proxy['RequireTLS']!r}"
    )

    # An unrelated target-group-level modification (connection pool config) must not touch
    # RequireTLS -- it is a proxy-level policy, not something a target group can override.
    rds.modify_db_proxy_target_group(
        DBProxyName=proxy_name,
        TargetGroupName="default",
        ConnectionPoolConfig={"MaxConnectionsPercent": 50},
    )
    proxy_after_tg_change = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]
    assert proxy_after_tg_change["RequireTLS"] is True, (
        "RequireTLS changed as a side effect of a target-group-level modification"
    )

    # Positive control: only an explicit ModifyDBProxy on RequireTLS changes it.
    rds.modify_db_proxy(DBProxyName=proxy_name, RequireTLS=False)
    proxy_after_explicit_change = _wait_require_tls(ctx, proxy_name, False, timeout_s=180)
    assert proxy_after_explicit_change is False, (
        f"an explicit ModifyDBProxy(RequireTLS=False) never took effect, "
        f"got {proxy_after_explicit_change!r}"
    )


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


def _create_db_proxy_with_retry(
    rds, *, proxy_name, role_arn, secret_arn, subnet_ids, sg_id, timeout_s: float
) -> None:
    """CreateDBProxy can fail transiently while the freshly-created IAM role/trust policy has not
    yet propagated to be assumable by rds.amazonaws.com; poll (bounded) instead of a bare sleep."""
    deadline = time.monotonic() + timeout_s
    last_err: Exception | None = None
    while time.monotonic() < deadline:
        try:
            rds.create_db_proxy(
                DBProxyName=proxy_name,
                EngineFamily="MYSQL",
                RoleArn=role_arn,
                VpcSubnetIds=subnet_ids,
                VpcSecurityGroupIds=[sg_id],
                Auth=[{"AuthScheme": "SECRETS", "IAMAuth": "DISABLED", "SecretArn": secret_arn}],
                RequireTLS=True,
                Tags=[{"Key": "sim2real:managed", "Value": "true"}],
            )
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code not in ("InvalidParameterValue", "InvalidParameterValueException"):
                raise
            last_err = exc
            time.sleep(5)
    raise AssertionError(f"create_db_proxy({proxy_name}) never succeeded (role propagation?): {last_err}")


def _wait_proxy_status(ctx, proxy_name, target_status, timeout_s=300, poll_s=10) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"proxy {proxy_name} never reached {target_status!r}, last status {last and last['Status']!r}"
    )


def _wait_require_tls(ctx, proxy_name, target_value, timeout_s=180, poll_s=10):
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]["RequireTLS"]
        if last == target_value:
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"proxy {proxy_name} RequireTLS never reached {target_value}, last observed {last!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
