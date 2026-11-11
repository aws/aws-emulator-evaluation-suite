"""describe-proxy-targets."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "describe-proxy-targets"
GROUP = 'proxy'
SERVICES = ['rds']

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _make_password():
    return "Sim2Real1" + uuid.uuid4().hex[:8] + "!"


def _rejection(fn):
    """Call fn() and return its botocore Error dict; raise if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"expected DescribeDBProxyTargets to reject, but it succeeded: {result!r}")


def _poll_until(probe, predicate, *, timeout_s=90, interval_s=2.0, description='condition'):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f'{description} not met within {timeout_s}s. Last result: {last!r}')


def _subnet_ids(ec2, min_count=2, *, ctx):
    subnets = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]).get("Subnets", [])
    by_vpc: dict = {}
    for s in subnets:
        by_vpc.setdefault(s["VpcId"], {}).setdefault(s["AvailabilityZone"], s["SubnetId"])
    if not by_vpc:
        raise AssertionError("no subnets available for RDS proxy")
    best = max(by_vpc.values(), key=len)
    ids = list(best.values())
    if len(ids) < min_count:
        raise AssertionError(f"fewer than {min_count} subnets in a single VPC")
    return ids


def _cleanup_role(iam, role_name):
    for pol in iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", []):
        iam.detach_role_policy(RoleName=role_name, PolicyArn=pol["PolicyArn"])
    iam.delete_role(RoleName=role_name)


def _ensure_rds_service_linked_role(iam):
    """Create AWSServiceRoleForRDS if missing; an account that never used RDS lacks it and
    CreateDBProxy needs it."""
    try:
        iam.create_service_linked_role(AWSServiceName="rds.amazonaws.com")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidInput":
            raise


def _create_proxy_with_retry(rds, *, timeout_s=90.0, interval_s=10.0, **kwargs):
    """Create the proxy, retrying InvalidParameterValue while the role's trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.create_db_proxy(**kwargs)
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code == "InvalidParameterValue" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


def _proxy(rds, name):
    try:
        proxies = rds.describe_db_proxies(DBProxyName=name).get("DBProxies", [])
        return proxies[0] if proxies else None
    except ClientError:
        return None


def _create_available_proxy(ctx, rds):
    sm = ctx.client("secretsmanager")
    iam = ctx.client("iam")
    ec2 = ctx.client("ec2")
    subnets = _subnet_ids(ec2, ctx=ctx)
    secret = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-secret-"),
        SecretString=json.dumps({"username": "admin", "password": _make_password()}),
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=secret["ARN"], ForceDeleteWithoutRecovery=True)
    )
    role_name = ctx.unique_name("sim2real-behav-role-")
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
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/SecretsManagerReadWrite"
    )
    _ensure_rds_service_linked_role(iam)
    proxy_name = ctx.unique_name("sim2real-behav-proxy-")
    _create_proxy_with_retry(
        rds,
        DBProxyName=proxy_name,
        EngineFamily="MYSQL",
        RoleArn=role["Role"]["Arn"],
        VpcSubnetIds=subnets,
        Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret["ARN"], "IAMAuth": "DISABLED"}],
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: rds.delete_db_proxy(DBProxyName=proxy_name))
    _poll_until(
        lambda: _proxy(rds, proxy_name),
        lambda p: p is not None and p.get("Status") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"proxy {proxy_name} available",
    )
    return proxy_name


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDBProxyTargets on a new proxy returns an empty Targets list, unfiltered and for the
    default target group; an unknown proxy name fails DBProxyNotFoundFault.
    """
    rds = ctx.client("rds")
    proxy_name = _create_available_proxy(ctx, rds)

    resp = rds.describe_db_proxy_targets(DBProxyName=proxy_name)
    assert "Targets" in resp, f"expected a Targets member on the response, got keys {sorted(resp)!r}"
    targets = resp["Targets"]
    assert targets == [], f"expected no registered targets on a fresh proxy, got {targets!r}"

    resp2 = rds.describe_db_proxy_targets(DBProxyName=proxy_name, TargetGroupName="default")
    assert "Targets" in resp2, f"expected a Targets member on the response, got keys {sorted(resp2)!r}"
    targets2 = resp2["Targets"]
    assert targets2 == [], f"expected no targets in the default target group, got {targets2!r}"

    bogus_proxy = ctx.unique_name("sim2real-behav-proxy-missing-")
    err = _rejection(lambda: rds.describe_db_proxy_targets(DBProxyName=bogus_proxy))
    assert err.get("Code") == "DBProxyNotFoundFault", f"unexpected error: {err}"
    assert err.get("Message") == f"DBProxy '{bogus_proxy}' not found.", (
        f"unexpected DBProxyNotFoundFault message: {err}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
