"""delete-db-proxy-with-dependent-endpoint-cascades."""
from __future__ import annotations

import json
import time


from behavioral_harness import tags

CHECK = "delete-db-proxy-with-dependent-endpoint-cascades"
GROUP = "negative-classes"
SERVICES = ["rds"]

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-proxyinuse"},
]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDBProxy on a proxy with a custom DBProxyEndpoint is accepted and cascades.

    Both the proxy and its endpoint then describe as not found, so no orphaned endpoint remains.
    """
    ec2 = ctx.client("ec2")
    subnet_ids = _default_vpc_subnets(ec2, ctx=ctx)
    if subnet_ids is None:
        raise AssertionError("no shared network VPC with subnets in 2+ AZs found in this account/region")

    rds = ctx.client("rds")
    iam = ctx.client("iam")
    secretsmanager = ctx.client("secretsmanager")

    secret_arn = _create_secret(ctx, secretsmanager)
    role_arn = _create_proxy_role(ctx, iam, secret_arn)

    proxy_name = ctx.unique_name("sim2real-proxyinuse-")
    _create_proxy_retrying_iam_propagation(
        rds, proxy_name, secret_arn=secret_arn, role_arn=role_arn, subnet_ids=subnet_ids
    )
    ctx.on_cleanup(lambda: _delete_proxy_ignore_missing(rds, proxy_name))
    _wait_proxy_status(ctx, proxy_name, "available", timeout_s=900)

    endpoint_name = ctx.unique_name("sim2real-proxyep-")
    rds.create_db_proxy_endpoint(
        DBProxyName=proxy_name, DBProxyEndpointName=endpoint_name, VpcSubnetIds=subnet_ids
    )
    ctx.on_cleanup(lambda: _delete_proxy_endpoint_ignore_missing(rds, endpoint_name))
    _wait_proxy_endpoint_status(ctx, endpoint_name, "available", timeout_s=300)

    # DeleteDBProxy while a custom endpoint still depends on it is accepted, not rejected.
    rds.delete_db_proxy(DBProxyName=proxy_name)

    _wait_proxy_gone(ctx, proxy_name, timeout_s=900)
    _wait_proxy_endpoint_gone(ctx, endpoint_name, timeout_s=900)

    absent_proxy_code, absent_proxy_message = _error_code(
        lambda: rds.describe_db_proxies(DBProxyName=proxy_name)
    )
    assert absent_proxy_code == "DBProxyNotFoundFault", f"unexpected error code {absent_proxy_code!r}"
    assert absent_proxy_message == f"DBProxy '{proxy_name}' not found.", (
        f"unexpected message {absent_proxy_message!r}"
    )
    absent_ep_code, absent_ep_message = _error_code(
        lambda: rds.describe_db_proxy_endpoints(DBProxyEndpointName=endpoint_name)
    )
    assert absent_ep_code == "DBProxyEndpointNotFoundFault", f"unexpected error code {absent_ep_code!r}"
    assert absent_ep_message == f"DBProxyEndpoint '{endpoint_name}' not found.", (
        f"unexpected message {absent_ep_message!r}"
    )


def _error_code(fn):
    """Call fn() and return its botocore error (code, message); raise if the call succeeds."""
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001 - classify below
        response = getattr(exc, "response", None)
        if response is not None:
            error = response.get("Error", {})
            return error.get("Code"), error.get("Message")
        raise
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _create_proxy_retrying_iam_propagation(
    rds, proxy_name, *, secret_arn, role_arn, subnet_ids, timeout_s=120, poll_s=10
) -> dict:
    """Create the proxy, retrying InvalidParameterValueException while the IAM role propagates."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    while True:
        try:
            return rds.create_db_proxy(
                DBProxyName=proxy_name,
                EngineFamily="POSTGRESQL",
                Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret_arn, "IAMAuth": "DISABLED"}],
                RoleArn=role_arn,
                VpcSubnetIds=subnet_ids,
                Tags=_MANAGED_TAGS,
            )
        except Exception as exc:  # noqa: BLE001 - classify below
            response = getattr(exc, "response", None)
            code = response.get("Error", {}).get("Code") if response else None
            if code != "InvalidParameterValueException":
                raise
            last_error = f"{code}: {exc}"
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"create_db_proxy {proxy_name} never succeeded (IAM propagation?): {last_error}"
                ) from exc
            time.sleep(poll_s)


def _default_vpc_subnets(ec2, *, ctx) -> list[str] | None:
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        return None
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        return None
    return list(by_az.values())[:3]


def _create_secret(ctx, secretsmanager) -> str:
    name = ctx.unique_name("sim2real-proxysecret-")
    secret = secretsmanager.create_secret(
        Name=name,
        SecretString=json.dumps({"username": "s2radmin", "password": "Sim2real-placeholder-1"}),
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(
        lambda: secretsmanager.delete_secret(SecretId=name, ForceDeleteWithoutRecovery=True)
    )
    return secret["ARN"]


def _create_proxy_role(ctx, iam, secret_arn: str) -> str:
    role_name = ctx.unique_name("sim2real-proxyrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=_MANAGED_TAGS
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_doc = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="sim2real-proxy-secret-access", PolicyDocument=json.dumps(policy_doc)
    )
    ctx.on_cleanup(
        lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="sim2real-proxy-secret-access")
    )
    return arn


def _delete_proxy_ignore_missing(rds, proxy_name) -> None:
    """Delete the proxy, retried while a transitional state refuses it, then wait until it is gone."""
    deadline = time.monotonic() + 300
    while True:
        try:
            rds.delete_db_proxy(DBProxyName=proxy_name)
            break
        except rds.exceptions.DBProxyNotFoundFault:
            return
        except rds.exceptions.InvalidDBProxyStateFault:
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)
    _wait_proxy_deleted(rds, proxy_name, timeout_s=600)


def _delete_proxy_endpoint_ignore_missing(rds, endpoint_name, timeout_s=600) -> None:
    """Delete the endpoint; not-found is clean, a transitional state is retried, the rest raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.delete_db_proxy_endpoint(DBProxyEndpointName=endpoint_name)
            return
        except rds.exceptions.DBProxyEndpointNotFoundFault:
            return
        except rds.exceptions.InvalidDBProxyEndpointStateFault:
            if time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _wait_proxy_deleted(rds, proxy_name, timeout_s=600) -> None:
    """Poll until the proxy describes as not found; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.describe_db_proxies(DBProxyName=proxy_name)
        except rds.exceptions.DBProxyNotFoundFault:
            return
        if time.monotonic() >= deadline:
            raise RuntimeError(f"DB proxy {proxy_name} still exists after {timeout_s}s")
        time.sleep(2)


def _wait_proxy_status(ctx, proxy_name, target_status, timeout_s=900, poll_s=20) -> dict:
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


def _wait_proxy_gone(ctx, proxy_name, timeout_s=300, poll_s=15) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_proxies(DBProxyName=proxy_name)
        except rds.exceptions.DBProxyNotFoundFault:
            return
        time.sleep(poll_s)
    raise AssertionError(f"proxy {proxy_name} was still visible after {timeout_s}s")


def _wait_proxy_endpoint_status(ctx, endpoint_name, target_status, timeout_s=300, poll_s=15) -> dict:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_proxy_endpoints(DBProxyEndpointName=endpoint_name)[
            "DBProxyEndpoints"
        ][0]
        if last["Status"] == target_status:
            return last
        time.sleep(poll_s)
    raise AssertionError(
        f"proxy endpoint {endpoint_name} never reached {target_status!r}, "
        f"last status {last and last['Status']!r}"
    )


def _wait_proxy_endpoint_gone(ctx, endpoint_name, timeout_s=300, poll_s=15) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_proxy_endpoints(DBProxyEndpointName=endpoint_name)
        except rds.exceptions.DBProxyEndpointNotFoundFault:
            return
        time.sleep(poll_s)
    raise AssertionError(f"proxy endpoint {endpoint_name} was still visible after {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
