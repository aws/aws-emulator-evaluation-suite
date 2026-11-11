"""db-proxy-endpoint-lifecycle."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "db-proxy-endpoint-lifecycle"
GROUP = "state-machine"
SERVICES = ["rds"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Additional DB proxy endpoint: creating -> available -> renamed -> deleted, distinct from the primary endpoint."""
    rds = ctx.client("rds")
    subnet_ids = _default_subnet_ids(ctx)
    subnet_group = _create_subnet_group(ctx, subnet_ids)

    secret_arn = _create_secret(ctx)
    role_arn = _create_proxy_role(ctx, secret_arn)

    cluster_id = ctx.unique_name("sim2real-behav-cl-")
    rds.create_db_cluster(
        DBClusterIdentifier=cluster_id,
        Engine="aurora-mysql",
        MasterUsername="simadmin",
        MasterUserPassword="Sim2RealBehav1",
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: _delete_cluster_and_wait(rds, cluster_id))
    _wait_cluster_status(ctx, cluster_id, {"available"})

    proxy_name = ctx.unique_name("sim2real-behav-proxy-")
    _create_proxy_with_retry(
        rds,
        DBProxyName=proxy_name,
        EngineFamily="MYSQL",
        RoleArn=role_arn,
        VpcSubnetIds=subnet_ids,
        Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret_arn, "IAMAuth": "DISABLED"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_proxy(DBProxyName=proxy_name))
    _wait_proxy_status(ctx, proxy_name, {"available"}, timeout_s=900.0)

    try:
        rds.register_db_proxy_targets(DBProxyName=proxy_name, DBClusterIdentifiers=[cluster_id])
    except ClientError:
        pass  # target registration health is not under test here; endpoint lifecycle is.

    endpoint_name = ctx.unique_name("sim2real-behav-pep-")
    rds.create_db_proxy_endpoint(
        DBProxyEndpointName=endpoint_name, DBProxyName=proxy_name, VpcSubnetIds=subnet_ids, TargetRole="READ_ONLY"
    )

    current_name = endpoint_name

    def _cleanup_endpoint():
        try:
            rds.delete_db_proxy_endpoint(DBProxyEndpointName=current_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "DBProxyEndpointNotFoundFault":
                raise

    ctx.on_cleanup(_cleanup_endpoint)

    endpoint = _wait_endpoint_status(ctx, endpoint_name, {"available"}, timeout_s=300.0)
    assert endpoint["TargetRole"] == "READ_ONLY", f"expected TargetRole READ_ONLY, got {endpoint.get('TargetRole')!r}"
    assert endpoint["IsDefault"] is False, f"custom endpoint should not be the proxy's default endpoint, got IsDefault={endpoint.get('IsDefault')!r}"

    renamed = endpoint_name + "-renamed"
    rds.modify_db_proxy_endpoint(DBProxyEndpointName=endpoint_name, NewDBProxyEndpointName=renamed)
    current_name = renamed
    endpoint = _wait_endpoint_status(ctx, renamed, {"available"}, timeout_s=300.0)
    assert endpoint["DBProxyEndpointName"] == renamed, f"expected renamed endpoint name {renamed!r}, got {endpoint.get('DBProxyEndpointName')!r}"

    # The primary (default) endpoint is distinct from this custom one and is unaffected.
    proxy = rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]
    assert proxy["Endpoint"], "primary proxy endpoint should still be present"
    assert proxy["Endpoint"] != endpoint["Endpoint"], (
        f"primary endpoint {proxy['Endpoint']!r} should differ from custom endpoint {endpoint['Endpoint']!r}"
    )

    rds.delete_db_proxy_endpoint(DBProxyEndpointName=renamed)
    _wait_endpoint_gone(ctx, renamed)

    code, message = _error_code(lambda: rds.describe_db_proxy_endpoints(DBProxyEndpointName=renamed))
    assert code == "DBProxyEndpointNotFoundFault", f"expected DBProxyEndpointNotFoundFault, got {code!r}"
    assert message == f"DBProxyEndpoint '{renamed}' not found.", f"unexpected not-found message {message!r}"


def _error_code(fn):
    """Call fn(); return its botocore Error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=900.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _default_subnet_ids(ctx, count: int = 3) -> list[str]:
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    ids = sorted({s["SubnetId"] for s in subnets})[:count]
    assert len(ids) >= 2, "need at least 2 subnets"
    return ids


def _create_subnet_group(ctx, subnet_ids: list[str]) -> str:
    rds = ctx.client("rds")
    name = ctx.unique_name("sim2real-behav-subnetgrp-")
    rds.create_db_subnet_group(
        DBSubnetGroupName=name, DBSubnetGroupDescription="sim2real behavioral check", SubnetIds=subnet_ids
    )
    ctx.on_cleanup(lambda: rds.delete_db_subnet_group(DBSubnetGroupName=name))
    return name


def _create_secret(ctx) -> str:
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    resp = sm.create_secret(
        Name=name,
        SecretString=json.dumps({"username": "simadmin", "password": "Sim2RealBehav1"}),
    )
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=resp["ARN"], ForceDeleteWithoutRecovery=True))
    return resp["ARN"]


def _create_proxy_role(ctx, secret_arn: str) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-proxyrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    policy_name = "sim2real-behav-secrets-access"
    access_policy = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "secretsmanager:GetSecretValue", "Resource": secret_arn}],
    }
    iam.put_role_policy(RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(access_policy))
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return role["Arn"]


def _create_proxy_with_retry(rds, *, timeout_s: float = 90.0, interval_s: float = 10.0, **kwargs) -> None:
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.create_db_proxy(**kwargs)
            return
        except ClientError as e:
            if e.response["Error"]["Code"] == "InvalidParameterValue" and time.monotonic() < deadline:
                time.sleep(interval_s)  # IAM role trust propagation delay
                continue
            raise


def _delete_cluster_and_wait(rds, cluster_id: str, timeout_s: float = 1200.0, interval_s: float = 20.0) -> None:
    """Delete the cluster and block until it reads not-found, so the subnet group it holds can go."""
    try:
        rds.delete_db_cluster(DBClusterIdentifier=cluster_id, SkipFinalSnapshot=True)
    except ClientError as e:
        if e.response["Error"]["Code"] != "DBClusterNotFoundFault":
            raise
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            rds.describe_db_clusters(DBClusterIdentifier=cluster_id)
        except ClientError as e:
            if e.response["Error"]["Code"] == "DBClusterNotFoundFault":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"DB cluster {cluster_id} was not deleted within {timeout_s}s")


def _wait_cluster_status(ctx, cluster_id: str, statuses: set[str], timeout_s: float = 1200.0, interval_s: float = 20.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_clusters(DBClusterIdentifier=cluster_id)["DBClusters"][0]

    return _poll_until(probe, lambda c: c["Status"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


def _wait_proxy_status(ctx, proxy_name: str, statuses: set[str], timeout_s: float = 900.0, interval_s: float = 10.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_proxies(DBProxyName=proxy_name)["DBProxies"][0]

    return _poll_until(probe, lambda p: p["Status"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


def _wait_endpoint_status(ctx, endpoint_name: str, statuses: set[str], timeout_s: float = 300.0, interval_s: float = 10.0) -> dict[str, Any]:
    rds = ctx.client("rds")

    def probe():
        return rds.describe_db_proxy_endpoints(DBProxyEndpointName=endpoint_name)["DBProxyEndpoints"][0]

    return _poll_until(probe, lambda e: e["Status"] in statuses, timeout_s=timeout_s, interval_s=interval_s)


def _wait_endpoint_gone(ctx, endpoint_name: str, timeout_s: float = 300.0, interval_s: float = 10.0) -> None:
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            resp = rds.describe_db_proxy_endpoints(DBProxyEndpointName=endpoint_name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "DBProxyEndpointNotFoundFault":
                return
            raise
        if not resp["DBProxyEndpoints"]:
            return
        time.sleep(interval_s)
    raise AssertionError(f"proxy endpoint {endpoint_name} was not deleted within {timeout_s}s")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
