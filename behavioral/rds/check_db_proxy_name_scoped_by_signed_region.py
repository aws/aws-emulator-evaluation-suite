"""db-proxy-name-scoped-by-signed-region."""
from __future__ import annotations

import json
import secrets
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "db-proxy-name-scoped-by-signed-region"
GROUP = 'proxy'
SERVICES = ['rds']

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _cleanup_role(iam, role_name):
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_db_proxy_with_retry(rds, *, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs):
    """CreateDBProxy, retrying InvalidParameterValue within a bounded budget while the new IAM role
    is not yet assumable by rds.amazonaws.com.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rds.create_db_proxy(**kwargs)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterValue" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _poll_until_gone(fn, *, timeout_s=180.0, interval_s=5.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "DBProxyNotFoundFault":
                return code
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"{description} not met within {timeout_s}s")
        time.sleep(interval_s)


def _make_proxy(ctx, region, name, role_arn):
    """Create the secret, subnets and proxy in *region*; return the DBProxy dict (teardown on ctx)."""
    rds = ctx.client("rds", region=region)
    sm = ctx.client("secretsmanager", region=region)

    # The shared network has exactly one subnet per availability zone, in zone order, so these
    # two subnets sit in two distinct zones, as a DB proxy requires.
    subnet_ids = ctx.network(region).subnet_ids[:2]
    secret = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-proxysecret-"),
        SecretString=json.dumps({"username": "sim2real", "password": secrets.token_urlsafe(18)}),
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret["ARN"], ForceDeleteWithoutRecovery=True))

    created = _create_db_proxy_with_retry(
        rds,
        DBProxyName=name,
        EngineFamily="POSTGRESQL",
        RoleArn=role_arn,
        VpcSubnetIds=subnet_ids,
        Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret["ARN"], "IAMAuth": "DISABLED"}],
        Tags=_MANAGED_TAGS,
    )

    def _cleanup_proxy():
        try:
            rds.delete_db_proxy(DBProxyName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "DBProxyNotFoundFault":
                raise
        _poll_until_gone(
            lambda: rds.describe_db_proxies(DBProxyName=name),
            timeout_s=600.0,
            interval_s=10.0,
            description=f"proxy {name} ({region}) gone after delete",
        )

    ctx.on_cleanup(_cleanup_proxy)
    return created["DBProxy"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The same DBProxyName in two signed regions creates two independent proxies: each ARN carries
    its own region and each region's DescribeDBProxies finds only its own proxy.
    """
    name = ctx.unique_name("sim2real-behav-rproxy-")
    east = "us-east-1" if ctx.region != "us-east-1" else "us-west-2"

    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-proxyrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Path="/sim2real/",
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _cleanup_role(iam, role_name))
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="secrets",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue", "kms:Decrypt"], "Resource": "*"}
                ],
            }
        ),
    )
    role_arn = role["Role"]["Arn"]

    east_proxy = _make_proxy(ctx, east, name, role_arn)
    west_proxy = _make_proxy(ctx, ctx.region, name, role_arn)

    assert east_proxy["DBProxyName"] == name, east_proxy["DBProxyName"]
    assert west_proxy["DBProxyName"] == name, west_proxy["DBProxyName"]
    east_arn = east_proxy["DBProxyArn"]
    west_arn = west_proxy["DBProxyArn"]
    assert f":rds:{east}:" in east_arn, f"east proxy ARN {east_arn!r} does not carry {east!r}"
    assert f":rds:{ctx.region}:" in west_arn, f"west proxy ARN {west_arn!r} does not carry {ctx.region!r}"
    assert east_arn != west_arn, (
        f"same-named proxies in two regions produced the SAME ARN {east_arn!r} -- "
        "the name is not actually region-scoped"
    )

    rds_east = ctx.client("rds", region=east)
    rds_west = ctx.client("rds", region=ctx.region)

    east_seen = rds_east.describe_db_proxies(DBProxyName=name)["DBProxies"]
    assert len(east_seen) == 1, f"expected exactly 1 proxy named {name!r} in {east}, got {east_seen!r}"
    assert east_seen[0]["DBProxyArn"] == east_arn, east_seen[0]["DBProxyArn"]

    west_seen = rds_west.describe_db_proxies(DBProxyName=name)["DBProxies"]
    assert len(west_seen) == 1, f"expected exactly 1 proxy named {name!r} in {ctx.region}, got {west_seen!r}"
    assert west_seen[0]["DBProxyArn"] == west_arn, west_seen[0]["DBProxyArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
