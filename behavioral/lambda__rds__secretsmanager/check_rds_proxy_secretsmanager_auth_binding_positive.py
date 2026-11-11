"""rds-proxy-secretsmanager-auth-binding-positive."""
from __future__ import annotations

import json
import time
import uuid
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rds-proxy-secretsmanager-auth-binding-positive"
GROUP = "resource-binding"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A proxy's Auth binding reports the Secrets Manager secret it was created with, and
    ModifyDBProxy re-points it to a different secret without falling back to the old one.
    """
    rds = ctx.client("rds")

    subnet_ids, sg_id = _default_vpc_network(ctx)
    secret_a_arn = _create_secret(ctx, "admin", f"S1m2Real{uuid.uuid4().hex[:12]}")
    role_arn, role_name = _create_proxy_role(ctx)

    proxy_name = _create_proxy(ctx, secret_a_arn, role_arn, subnet_ids, sg_id)
    _wait_proxy_available(ctx, proxy_name, timeout_s=480)

    auth = _describe_auth(ctx, proxy_name)
    assert auth.get("SecretArn") == secret_a_arn, (
        f"expected the proxy's live Auth binding to resolve to secret A right after "
        f"creation, got {auth!r}"
    )

    # --- rebind the SAME proxy to a DIFFERENT real Secrets Manager secret. The Auth field
    # is proxy config metadata (not a live connection attempt), so it need not wait for
    # Status=available again -- poll DescribeDBProxies until the Auth entry itself updates. ---
    secret_b_arn = _create_secret(ctx, "admin2", f"S1m2Real{uuid.uuid4().hex[:12]}")
    rds.modify_db_proxy(
        DBProxyName=proxy_name,
        Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret_b_arn, "IAMAuth": "DISABLED"}],
    )
    rebound_auth = _poll_auth_secret(ctx, proxy_name, secret_b_arn, timeout_s=30)
    assert rebound_auth.get("SecretArn") == secret_b_arn, (
        f"expected the proxy's Auth binding to resolve to secret B once rebound via "
        f"ModifyDBProxy, got {rebound_auth!r}"
    )
    assert rebound_auth.get("SecretArn") != secret_a_arn, (
        f"proxy must not still resolve to the old secret A after rebinding, got {rebound_auth!r}"
    )


def _default_vpc_network(ctx) -> tuple[list[str], str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not have subnets in at least 2 availability zones")
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    return list(by_az.values())[:2], sgs[0]["GroupId"]


def _create_secret(ctx, username: str, password: str) -> str:
    secrets = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-rdsproxy-secret-")
    resp = secrets.create_secret(
        Name=name,
        SecretString=json.dumps({"username": username, "password": password}),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )
    arn = resp["ARN"]
    ctx.on_cleanup(lambda: secrets.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    return arn


def _create_proxy_role(ctx) -> tuple[str, str]:
    """Trust policy only: the Auth binding is config metadata, so the role never needs to read
    the secret (that matters only for a real backend connection, which this check never makes)."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rdsproxy-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role["Arn"], role_name


def _describe_auth(ctx, proxy_name: str) -> dict[str, Any]:
    rds = ctx.client("rds")
    proxies = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"]
    assert len(proxies) == 1, f"expected exactly one proxy named {proxy_name!r}, got {proxies!r}"
    auth_entries = proxies[0]["Auth"]
    assert len(auth_entries) == 1, f"expected exactly one Auth entry, got {auth_entries!r}"
    return auth_entries[0]


def _poll_auth_secret(ctx, proxy_name: str, expected_secret_arn: str, timeout_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: dict[str, Any] = {}
    while time.monotonic() < deadline:
        last = _describe_auth(ctx, proxy_name)
        if last.get("SecretArn") == expected_secret_arn:
            return last
        time.sleep(3)
    return last


def _create_proxy(ctx, secret_arn: str, role_arn: str, subnet_ids: list[str], sg_id: str) -> str:
    """CreateDBProxy can fail transiently while the freshly-created IAM role/trust policy has not
    yet propagated to be assumable by rds.amazonaws.com; poll (bounded) instead of a bare sleep."""
    rds = ctx.client("rds")
    proxy_name = ctx.unique_name("sim2real-rdsproxy-")
    deadline = time.monotonic() + 60
    last_exc: Exception | None = None
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
                Tags=[{"Key": "sim2real", "Value": "true"}],
            )
            break
        except Exception as exc:  # noqa: BLE001 - IAM propagation lag, retry until the budget runs out
            last_exc = exc
            time.sleep(5)
    else:
        raise AssertionError(f"CreateDBProxy did not succeed within 60s (IAM propagation?): {last_exc!r}")
    ctx.on_cleanup(lambda: _delete_proxy(ctx, proxy_name))
    return proxy_name


def _delete_proxy(ctx, proxy_name: str) -> None:
    rds = ctx.client("rds")
    try:
        rds.delete_db_proxy(DBProxyName=proxy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "DBProxyNotFoundFault":
            raise
        return
    deadline = time.monotonic() + 300
    while time.monotonic() < deadline:
        try:
            rds.describe_db_proxies(DBProxyName=proxy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "DBProxyNotFoundFault":
                raise
            return
        time.sleep(10)


def _wait_proxy_available(ctx, proxy_name: str, timeout_s: float) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        proxies = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"]
        status = proxies[0]["Status"] if proxies else None
        if status == "available":
            return
        time.sleep(5)
    raise AssertionError(f"RDS Proxy {proxy_name} never reached status 'available' (last: {status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
