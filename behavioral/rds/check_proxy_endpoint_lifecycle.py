"""proxy-endpoint-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError


from behavioral_harness import tags
import secrets

CHECK = "proxy-endpoint-lifecycle"
GROUP = 'proxy'
SERVICES = ['rds']

ERR_PROXY_ENDPOINT_NOT_FOUND = "DBProxyEndpointNotFoundFault"

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _error_code(fn):
    """Call fn(); return its botocore error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s=600, interval_s=5, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _default_db_subnet_ids(ctx, count=2):
    """Return *count* default-VPC subnet ids in distinct AZs."""
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}]).get("Vpcs", [])
    if not vpcs:
        raise AssertionError(f"the run's shared network {ctx.network().vpc_id} is not visible")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    by_az: dict[str, str] = {}
    for subnet in sorted(subnets, key=lambda s: s["SubnetId"]):
        by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    ids = [by_az[az] for az in sorted(by_az)][:count]
    if len(ids) < count:
        raise AssertionError(f"shared network has only {len(ids)} usable subnets; need {count}")
    return ids


def _cleanup_role(iam, role_name):
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _create_proxy_prerequisites(ctx):
    """Create the IAM role + Secrets Manager secret + 2-AZ subnets a DB proxy needs.

    Returns (role_arn, secret_arn, subnet_ids); all teardown is registered on ctx.
    """
    subnet_ids = _default_db_subnet_ids(ctx, count=2)
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-proxyrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "rds.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
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
                    {
                        "Effect": "Allow",
                        "Action": ["secretsmanager:GetSecretValue", "kms:Decrypt"],
                        "Resource": "*",
                    }
                ],
            }
        ),
    )
    sm = ctx.client("secretsmanager")
    secret = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-proxysecret-"),
        SecretString=json.dumps({"username": "sim2real", "password": "Aa1!" + secrets.token_urlsafe(18)}),
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=secret["ARN"], ForceDeleteWithoutRecovery=True)
    )
    return role["Role"]["Arn"], secret["ARN"], subnet_ids


def _create_db_proxy_with_retry(rds, *, timeout_s=90, interval_s=10, **kwargs):
    """create_db_proxy rejects with InvalidParameterValue until the new role's trust policy has
    propagated to the RDS service; retry on that specific code instead of guessing a sleep."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.create_db_proxy(**kwargs)
            return
        except ClientError as exc:
            if (
                exc.response.get("Error", {}).get("Code") == "InvalidParameterValue"
                and time.monotonic() < deadline
            ):
                time.sleep(interval_s)
                continue
            raise


def _describe_proxy_endpoint(rds, name):
    try:
        resp = rds.describe_db_proxy_endpoints(DBProxyEndpointName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == ERR_PROXY_ENDPOINT_NOT_FOUND:
            return None
        raise
    eps = resp.get("DBProxyEndpoints", [])
    return eps[0] if eps else None


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteDBProxyEndpoint removes an additional endpoint of a real proxy, which then reads
    DBProxyEndpointNotFoundFault, and an unknown DBProxyEndpointName is rejected the same way."""
    rds = ctx.client("rds")
    role_arn, secret_arn, subnet_ids = _create_proxy_prerequisites(ctx)

    proxy_name = ctx.unique_name("sim2real-behav-proxy-")
    _create_db_proxy_with_retry(
        rds,
        DBProxyName=proxy_name,
        EngineFamily="MYSQL",
        RoleArn=role_arn,
        VpcSubnetIds=subnet_ids,
        Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret_arn, "IAMAuth": "DISABLED"}],
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_proxy(DBProxyName=proxy_name))
    _poll_until(
        lambda: (rds.describe_db_proxies(DBProxyName=proxy_name).get("DBProxies") or [None])[0],
        lambda p: p is not None and p.get("Status") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"db proxy {proxy_name} available",
    )

    ep_name = ctx.unique_name("sim2real-behav-proxyep-")
    rds.create_db_proxy_endpoint(
        DBProxyName=proxy_name,
        DBProxyEndpointName=ep_name,
        VpcSubnetIds=subnet_ids,
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _unless_gone(lambda: rds.delete_db_proxy_endpoint(DBProxyEndpointName=ep_name), "DBProxyEndpointNotFoundFault"))
    _poll_until(
        lambda: _describe_proxy_endpoint(rds, ep_name),
        lambda e: e is not None and e.get("Status") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"db proxy endpoint {ep_name} available",
    )

    rds.delete_db_proxy_endpoint(DBProxyEndpointName=ep_name)
    _poll_until(
        lambda: _describe_proxy_endpoint(rds, ep_name),
        lambda e: e is None,
        timeout_s=300,
        interval_s=10,
        description=f"db proxy endpoint {ep_name} deleted",
    )

    dead_code, dead_message = _error_code(lambda: rds.delete_db_proxy_endpoint(DBProxyEndpointName=ep_name))
    assert dead_code == ERR_PROXY_ENDPOINT_NOT_FOUND, (
        f"deleting the already-deleted endpoint {ep_name} again should still reject with "
        f"{ERR_PROXY_ENDPOINT_NOT_FOUND!r}, got {dead_code!r}"
    )
    assert dead_message == f"DBProxyEndpoint '{ep_name}' not found.", dead_message

    bogus_ep = ctx.unique_name("sim2real-behav-proxyep-missing-")
    code, message = _error_code(
        lambda: rds.delete_db_proxy_endpoint(DBProxyEndpointName=bogus_ep)
    )
    assert code == ERR_PROXY_ENDPOINT_NOT_FOUND, f"unexpected error code: {code}"
    assert message == f"DBProxyEndpoint '{bogus_ep}' not found.", message


def _unless_gone(fn, *codes, message=None):
    """Run a teardown delete; a resource the check already removed is not a failure."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        if err.get("Code") not in codes or (message is not None and message not in err.get("Message", "")):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
