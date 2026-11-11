"""rds-proxy-secret-arn-resolution."""

from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags

CHECK = "rds-proxy-secret-arn-resolution"
GROUP = "resource-binding"
SERVICES = ["lambda", "rds", "secretsmanager"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DB proxy's Auth entry resolves to the exact Secrets Manager ARN it was configured
    with, as reported back by DescribeDBProxies."""
    ctx.client("ec2")
    sm = ctx.client("secretsmanager")
    rds = ctx.client("rds")
    sts = ctx.client("sts")

    vpc_id, subnet_ids, sg_id = _default_vpc_prereqs(ctx)
    account_id = sts.get_caller_identity()["Account"]

    secret = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-proxy-secret-"),
        SecretString=json.dumps(
            {"username": "admin", "password": "ProxyAuthPassw0rd!23"}
        ),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    )

    role_arn = _create_proxy_role(ctx, secret_arn, account_id)

    proxy_name = ctx.unique_name("sim2real-behav-proxy-")
    _create_db_proxy(
        ctx,
        proxy_name=proxy_name,
        role_arn=role_arn,
        secret_arn=secret_arn,
        subnet_ids=subnet_ids,
        sg_id=sg_id,
    )

    proxy = _wait_for_proxy_available(ctx, proxy_name, timeout_s=900.0)

    assert len(proxy["Auth"]) == 1
    auth = proxy["Auth"][0]
    assert auth["SecretArn"] == secret_arn
    assert auth["AuthScheme"] == "SECRETS"


def _default_vpc_prereqs(ctx: Any) -> tuple[str, list[str], str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])[
        "Vpcs"
    ]
    if not vpcs:
        raise AssertionError(
            "no shared network VPC available in this account/region to host the DB proxy"
        )
    vpc_id = vpcs[0]["VpcId"]

    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])[
        "Subnets"
    ]
    by_az: dict[str, str] = {}
    for subnet in subnets:
        by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(
            "shared network VPC does not span 2+ availability zones required by RDS Proxy"
        )
    subnet_ids = list(by_az.values())[:3]

    sgs = ec2.describe_security_groups(
        Filters=[
            {"Name": "vpc-id", "Values": [vpc_id]},
            {"Name": "group-name", "Values": ["default"]},
        ]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    sg_id = sgs[0]["GroupId"]
    return vpc_id, subnet_ids, sg_id


def _create_proxy_role(ctx: Any, secret_arn: str, account_id: str) -> str:
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
            {
                "Effect": "Allow",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": secret_arn,
            }
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="proxy-secret-access",
        PolicyDocument=json.dumps(policy_doc),
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(
            RoleName=role_name, PolicyName="proxy-secret-access"
        )
    )
    return role_arn


def _create_db_proxy(
    ctx: Any,
    *,
    proxy_name: str,
    role_arn: str,
    secret_arn: str,
    subnet_ids: list[str],
    sg_id: str,
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
                Auth=[
                    {
                        "AuthScheme": "SECRETS",
                        "SecretArn": secret_arn,
                        "IAMAuth": "DISABLED",
                    }
                ],
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
    raise AssertionError(
        f"create_db_proxy({proxy_name}) never succeeded (role propagation?): {last_err}"
    )


def _wait_for_proxy_available(
    ctx: Any, proxy_name: str, timeout_s: float = 900.0
) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = rds.describe_db_proxies(DBProxyName=proxy_name)
        proxy = resp["DBProxies"][0]
        last_status = proxy["Status"]
        if last_status == "available":
            return proxy
        if last_status in ("incompatible-network", "insufficient-resource-limits"):
            raise AssertionError(
                f"DB proxy {proxy_name} entered unrecoverable status {last_status}"
            )
        time.sleep(2)
    raise AssertionError(
        f"DB proxy {proxy_name} never became available (last status={last_status})"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
