"""db-proxy-tls-required-server-enforced."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "db-proxy-tls-required-server-enforced"
GROUP = "server-side"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A DBProxy created with RequireTLS=True reads back True and keeps it across ModifyDBProxy
    calls that omit RequireTLS (IdleClientTimeout, then DebugLogging); only an explicit
    ModifyDBProxy(RequireTLS=False) turns it off."""
    rds = ctx.client("rds")
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    secretsmanager = ctx.client("secretsmanager")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    subnet_ids = list(by_az.values())[:2]
    if len(subnet_ids) < 2:
        raise AssertionError(f"VPC {vpc_id} does not have subnets in at least two AZs")

    secret_name = ctx.unique_name("sim2real-rdstls-secret-")
    secret = secretsmanager.create_secret(
        Name=secret_name,
        SecretString=json.dumps({"username": "s2radmin", "password": "Sim2RealTmpPwd123!"}),
    )
    secret_arn = secret["ARN"]
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=secret_arn, ForceDeleteWithoutRecovery=True)
    )

    role_name = ctx.unique_name("sim2real-rdstls-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = iam.get_role(RoleName=role_name)["Role"]["Arn"]
    policy_name = "sim2real-rdstls-secret-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": "secretsmanager:GetSecretValue",
                        "Resource": secret_arn,
                    }
                ],
            }
        ),
    )

    def _cleanup_role() -> None:
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)

    _ensure_rds_service_linked_role(iam)

    proxy_name = ctx.unique_name("sim2real-rdstlsproxy-")
    _create_db_proxy_with_role_propagation_retry(
        rds,
        DBProxyName=proxy_name,
        EngineFamily="POSTGRESQL",
        Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret_arn, "IAMAuth": "DISABLED"}],
        RoleArn=role_arn,
        VpcSubnetIds=subnet_ids,
        RequireTLS=True,
    )
    ctx.on_cleanup(lambda: _delete_proxy_if_exists(rds, proxy_name))

    status = _wait_for_proxy_status(rds, proxy_name, "available", timeout_s=600)
    assert status == "available", f"proxy never reached 'available' (last status={status!r})"

    created = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]
    assert created["RequireTLS"] is True, (
        f"proxy created with RequireTLS=True should read back True, got {created['RequireTLS']!r}"
    )

    # A proxy stays 'modifying' briefly after each ModifyDBProxy and another modify then raises
    # InvalidDBProxyStateFault, so wait for 'available' after every modify.
    rds.modify_db_proxy(DBProxyName=proxy_name, IdleClientTimeout=2000)
    settled_1 = _wait_for_proxy_status(rds, proxy_name, "available", timeout_s=120)
    assert settled_1 == "available", f"proxy never settled back to 'available' (got {settled_1!r})"
    after_1 = _wait_for_idle_timeout(rds, proxy_name, want=2000, timeout_s=60)
    assert after_1["IdleClientTimeout"] == 2000, "unrelated modify #1 never took effect"
    assert after_1["RequireTLS"] is True, (
        f"RequireTLS reverted after an unrelated ModifyDBProxy (IdleClientTimeout), "
        f"got {after_1['RequireTLS']!r}"
    )

    rds.modify_db_proxy(DBProxyName=proxy_name, DebugLogging=True)
    settled_2 = _wait_for_proxy_status(rds, proxy_name, "available", timeout_s=120)
    assert settled_2 == "available", f"proxy never settled back to 'available' (got {settled_2!r})"
    after_2 = _wait_for_debug_logging(rds, proxy_name, want=True, timeout_s=60)
    assert after_2["DebugLogging"] is True, "unrelated modify #2 never took effect"
    assert after_2["RequireTLS"] is True, (
        f"RequireTLS reverted after an unrelated ModifyDBProxy (DebugLogging), "
        f"got {after_2['RequireTLS']!r}"
    )

    rds.modify_db_proxy(DBProxyName=proxy_name, RequireTLS=False)
    settled_3 = _wait_for_proxy_status(rds, proxy_name, "available", timeout_s=120)
    assert settled_3 == "available", f"proxy never settled back to 'available' (got {settled_3!r})"
    disabled = _wait_for_require_tls(rds, proxy_name, want=False, timeout_s=60)
    assert disabled["RequireTLS"] is False, (
        f"an explicit ModifyDBProxy(RequireTLS=False) never took effect, "
        f"got {disabled['RequireTLS']!r}"
    )


def _ensure_rds_service_linked_role(iam) -> None:
    """Create AWSServiceRoleForRDS, which CreateDBProxy needs; a new account may not have it.

    It is a shared account-level role, so it is not torn down."""
    try:
        iam.create_service_linked_role(AWSServiceName="rds.amazonaws.com")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidInput":
            raise


def _create_db_proxy_with_role_propagation_retry(rds, timeout_s: float = 90.0, **kwargs) -> None:
    """CreateDBProxy, retrying InvalidParameterValue while a just-created IAM role propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.create_db_proxy(**kwargs)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterValue" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _wait_for_proxy_status(rds, proxy_name: str, want: str, timeout_s: float) -> str | None:
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]["Status"]
        if status == want:
            return status
        time.sleep(2)
    return status


def _wait_for_idle_timeout(rds, proxy_name: str, want: int, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    proxy = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]
    while time.monotonic() < deadline:
        proxy = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]
        if proxy["IdleClientTimeout"] == want:
            return proxy
        time.sleep(5)
    return proxy


def _wait_for_debug_logging(rds, proxy_name: str, want: bool, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    proxy = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]
    while time.monotonic() < deadline:
        proxy = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]
        if proxy["DebugLogging"] is want:
            return proxy
        time.sleep(5)
    return proxy


def _wait_for_require_tls(rds, proxy_name: str, want: bool, timeout_s: float) -> dict:
    deadline = time.monotonic() + timeout_s
    proxy = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]
    while time.monotonic() < deadline:
        proxy = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]
        if proxy["RequireTLS"] is want:
            return proxy
        time.sleep(5)
    return proxy


def _delete_proxy_if_exists(rds, name: str, timeout_s: float = 900.0) -> None:
    """Delete the proxy once it leaves 'creating'; not-found is clean, every other error raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            proxies = rds.describe_db_proxies(DBProxyName=name)["DBProxies"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "DBProxyNotFoundFault":
                return
            raise
        if not proxies:
            return
        if proxies[0]["Status"] != "creating":
            try:
                rds.delete_db_proxy(DBProxyName=name)
                return
            except ClientError as exc:
                code = exc.response["Error"]["Code"]
                if code == "DBProxyNotFoundFault":
                    return
                if code != "InvalidDBProxyStateFault" or time.monotonic() >= deadline:
                    raise
        if time.monotonic() >= deadline:
            raise RuntimeError(f"DB proxy {name} still 'creating' after {timeout_s}s; not deleted")
        time.sleep(2)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
