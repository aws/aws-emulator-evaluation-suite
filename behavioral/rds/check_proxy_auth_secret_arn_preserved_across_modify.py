"""proxy-auth-secret-arn-preserved-across-modify."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "proxy-auth-secret-arn-preserved-across-modify"
GROUP = "representation"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DBProxy's Auth[0].SecretArn set at CreateDBProxy time remains byte-identical after a
    ModifyDBProxy call that changes only IdleClientTimeout (and omits Auth entirely) -- proving
    the unrelated modify does not incidentally mutate or wipe the stored secret reference."""
    rds = ctx.client("rds")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    _vpc_id, az_subnets = _pick_azs_with_subnets(ctx, count=2)
    subnet_ids = [az_subnets[0]["SubnetId"], az_subnets[1]["SubnetId"]]

    fake_role_arn = f"arn:aws:iam::{account_id}:role/{ctx.unique_name('sim2real-rdsproxy-role-')}"
    fake_secret_arn = (
        f"arn:aws:secretsmanager:{ctx.region}:{account_id}:secret:"
        f"{ctx.unique_name('sim2real-rdsproxy-secret-')}-abcdef"
    )
    auth = [{"AuthScheme": "SECRETS", "SecretArn": fake_secret_arn, "IAMAuth": "DISABLED"}]

    proxy_name = ctx.unique_name("sim2real-rdsproxy-")
    rds.create_db_proxy(
        DBProxyName=proxy_name,
        EngineFamily="MYSQL",
        Auth=auth,
        RoleArn=fake_role_arn,
        VpcSubnetIds=subnet_ids,
        IdleClientTimeout=900,
        Tags=[
            {"Key": "sim2real:managed", "Value": "true"},
            {"Key": "sim2real:prefix", "Value": "sim2real-rdsproxy"},
        ],
    )
    ctx.on_cleanup(lambda: _delete_proxy(rds, proxy_name))

    status = _wait_for_proxy_status(rds, proxy_name, "available", timeout_s=600)
    assert status == "available", f"proxy never reached 'available' (last status={status!r})"

    before = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]
    assert before["Auth"][0]["SecretArn"] == fake_secret_arn, (
        f"expected SecretArn {fake_secret_arn!r} right after create, got "
        f"{before['Auth'][0].get('SecretArn')!r}"
    )

    # Modify ONLY IdleClientTimeout; Auth is deliberately omitted from the request.
    rds.modify_db_proxy(DBProxyName=proxy_name, IdleClientTimeout=1800)

    after = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]
    assert after["IdleClientTimeout"] == 1800, (
        f"expected the modify to take effect (IdleClientTimeout=1800), got "
        f"{after['IdleClientTimeout']!r}"
    )
    assert after["Auth"][0]["SecretArn"] == fake_secret_arn, (
        f"SecretArn changed after an unrelated ModifyDBProxy call: before="
        f"{fake_secret_arn!r} after={after['Auth'][0].get('SecretArn')!r}"
    )


def _pick_azs_with_subnets(ctx, count: int = 2) -> tuple[str, list[dict]]:
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
            f"VPC {vpc_id} has subnets in only {len(by_az)} AZ(s); need >= {count} for this test"
        )
    return vpc_id, list(by_az.values())[:count]


def _wait_for_proxy_status(rds, proxy_name: str, want: str, timeout_s: float) -> str | None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]["Status"]
        if status == want:
            return status
        time.sleep(2)
    return status


def _delete_proxy(rds, proxy_name: str) -> None:
    """Delete the proxy and poll until DescribeDBProxies answers DBProxyNotFoundFault; any other
    error, or the deadline, raises."""
    from botocore.exceptions import ClientError

    try:
        rds.delete_db_proxy(DBProxyName=proxy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "DBProxyNotFoundFault":
            return
        raise
    deadline = time.monotonic() + 600
    while True:
        try:
            rds.describe_db_proxies(DBProxyName=proxy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBProxyNotFoundFault":
                return
            raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"DB proxy {proxy_name} still listed 600s after DeleteDBProxy")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
