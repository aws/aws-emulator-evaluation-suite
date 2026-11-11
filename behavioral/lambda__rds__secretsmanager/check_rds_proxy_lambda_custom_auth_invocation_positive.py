"""rds-proxy-lambda-custom-auth-invocation-positive."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "rds-proxy-lambda-custom-auth-invocation-positive"
GROUP = "resource-binding"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RDS Proxy has no Lambda authorizer: a proxy reaches Status available with exactly one Auth
    entry, the configured secret ARN with AuthScheme SECRETS, and no Lambda reference."""
    rds = ctx.client("rds")
    subnet_ids, sg_id = _default_vpc_network(ctx)
    secret_arn = _create_secret(ctx, "admin", f"S1m2Real{uuid.uuid4().hex[:12]}")
    role_arn, _role_name = _create_proxy_role(ctx, secret_arn)
    proxy_name = _create_proxy(ctx, secret_arn, role_arn, subnet_ids, sg_id)

    status = _poll_proxy_terminal_status(ctx, proxy_name, timeout_s=900)
    assert status == "available", (
        f"expected the proxy to reach a genuinely operational Status=available once its "
        f"Secrets Manager binding resolved, got {status!r}"
    )

    proxies = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"]
    assert len(proxies) == 1, f"expected exactly one proxy named {proxy_name!r}, got {proxies!r}"
    auth_entries = proxies[0]["Auth"]
    assert len(auth_entries) == 1, f"expected exactly one Auth entry, got {auth_entries!r}"
    auth = auth_entries[0]
    # The only binding target RDS Proxy resolves is the Secrets Manager secret ARN we gave
    # it -- the real response shape has no Lambda ARN / authorizer field of any kind.
    assert auth.get("SecretArn") == secret_arn, f"expected the configured secret ARN back, got {auth!r}"
    assert auth.get("AuthScheme") == "SECRETS", f"expected AuthScheme=SECRETS, got {auth!r}"
    assert not any(
        "lambda" in str(key).lower() or "arn:aws:lambda" in str(value).lower()
        for key, value in auth.items()
    ), f"unexpected Lambda-shaped field in a real RDS Proxy Auth entry: {auth!r}"


def _default_vpc_network(ctx) -> tuple[list[str], str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to place the RDS Proxy")
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
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    arn = resp["ARN"]
    ctx.on_cleanup(lambda: secrets.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))
    return arn


def _create_proxy_role(ctx, allowed_secret_arn: str) -> tuple[str, str]:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-rdsproxy-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_name = "secrets-access"
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": allowed_secret_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    _poll_role_assumable(ctx, role_name, timeout_s=60)
    return role["Arn"], role_name


def _poll_role_assumable(ctx, role_name: str, timeout_s: float) -> None:
    """IAM roles are eventually consistent: poll GetRole until it reads back cleanly instead
    of sleeping a fixed duration before using it."""
    iam = ctx.client("iam")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        role = iam.get_role(RoleName=role_name)["Role"]
        if role.get("RoleName") == role_name:
            return
        time.sleep(2)
    raise AssertionError(f"IAM role {role_name} never became readable within {timeout_s}s")


def _create_proxy(ctx, secret_arn: str, role_arn: str, subnet_ids: list[str], sg_id: str) -> str:
    rds = ctx.client("rds")
    proxy_name = ctx.unique_name("sim2real-rdsproxy-")
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


def _poll_proxy_terminal_status(ctx, proxy_name: str, timeout_s: float) -> str | None:
    """Poll DescribeDBProxies until the proxy Status leaves the transient 'creating' state."""
    rds = ctx.client("rds")
    terminal = {"available", "incompatible-network", "insufficient-resource-limits"}
    deadline = time.monotonic() + timeout_s
    status: str | None = None
    while time.monotonic() < deadline:
        proxies = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"]
        status = proxies[0]["Status"] if proxies else None
        if status in terminal:
            return status
        time.sleep(2)
    return status


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
