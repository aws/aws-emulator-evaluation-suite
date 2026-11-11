"""describe-proxy-target-groups."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "describe-proxy-target-groups"
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
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


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


def _proxy(rds, name):
    try:
        proxies = rds.describe_db_proxies(DBProxyName=name).get("DBProxies", [])
        return proxies[0] if proxies else None
    except ClientError:
        return None


def _create_db_proxy_once_role_usable(rds, *, timeout_s=60, interval_s=5.0, **kwargs):
    """Create the proxy, retrying (bounded) while the new IAM role's trust policy propagates."""
    deadline = time.monotonic() + timeout_s
    last_error = None
    while True:
        try:
            return rds.create_db_proxy(**kwargs)
        except ClientError as exc:
            last_error = exc
            if time.monotonic() >= deadline:
                raise AssertionError(
                    f"create_db_proxy did not succeed within {timeout_s}s of role creation "
                    f"(IAM propagation); last error: {last_error}"
                ) from last_error
            time.sleep(interval_s)


def _delete_proxy_if_present(rds, name):
    try:
        rds.delete_db_proxy(DBProxyName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "DBProxyNotFoundFault":
            raise


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
    proxy_name = ctx.unique_name("sim2real-behav-proxy-")
    _create_db_proxy_once_role_usable(
        rds,
        DBProxyName=proxy_name,
        EngineFamily="MYSQL",
        RoleArn=role["Role"]["Arn"],
        VpcSubnetIds=subnets,
        Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret["ARN"], "IAMAuth": "DISABLED"}],
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: _delete_proxy_if_present(rds, proxy_name))
    _poll_until(
        lambda: _proxy(rds, proxy_name),
        lambda p: p is not None and p.get("Status") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"proxy {proxy_name} available",
    )
    return proxy_name


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A new proxy has one "default" target group (IsDefault=True), unfiltered and by name.

    Unknown proxy and deleted proxy fail DBProxyNotFoundFault; unknown group fails
    DBProxyTargetGroupNotFoundFault.
    """
    rds = ctx.client("rds")
    proxy_name = _create_available_proxy(ctx, rds)

    resp = rds.describe_db_proxy_target_groups(DBProxyName=proxy_name)
    groups = resp.get("TargetGroups", [])
    assert len(groups) == 1, f"expected exactly one default target group, got {groups}"
    assert groups[0]["TargetGroupName"] == "default", (
        f"expected TargetGroupName 'default', got {groups[0]['TargetGroupName']!r}"
    )
    assert groups[0]["IsDefault"] is True, f"expected IsDefault True, got {groups[0]['IsDefault']!r}"

    resp2 = rds.describe_db_proxy_target_groups(DBProxyName=proxy_name, TargetGroupName="default")
    assert resp2["TargetGroups"][0]["TargetGroupName"] == "default", (
        f"expected TargetGroupName 'default' when filtering by name, "
        f"got {resp2['TargetGroups'][0]['TargetGroupName']!r}"
    )

    bogus_proxy = ctx.unique_name("sim2real-behav-proxy-missing-")
    err = _rejection(lambda: rds.describe_db_proxy_target_groups(DBProxyName=bogus_proxy))
    assert err.get("Code") == "DBProxyNotFoundFault", f"unexpected error: {err}"
    assert err.get("Message") == f"DBProxy '{bogus_proxy}' not found.", (
        f"unexpected DBProxyNotFoundFault message: {err}"
    )

    bogus_group = ctx.unique_name("sim2real-behav-tg-missing-")
    err2 = _rejection(
        lambda: rds.describe_db_proxy_target_groups(
            DBProxyName=proxy_name, TargetGroupName=bogus_group
        )
    )
    assert err2.get("Code") == "DBProxyTargetGroupNotFoundFault", f"unexpected error: {err2}"
    assert err2.get("Message") == f"Requested resource not found - TargetGroup: {bogus_group}", (
        f"unexpected DBProxyTargetGroupNotFoundFault message: {err2}"
    )

    _delete_proxy_if_present(rds, proxy_name)
    _poll_until(
        lambda: _proxy(rds, proxy_name),
        lambda p: p is None,
        timeout_s=300,
        interval_s=10,
        description=f"proxy {proxy_name} deleted",
    )
    err3 = _rejection(lambda: rds.describe_db_proxy_target_groups(DBProxyName=proxy_name))
    assert err3.get("Code") == "DBProxyNotFoundFault", (
        f"describe_db_proxy_target_groups on a deleted proxy returned {err3}, "
        f"expected DBProxyNotFoundFault"
    )
    assert err3.get("Message") == f"DBProxy '{proxy_name}' not found.", (
        f"unexpected DBProxyNotFoundFault message for a deleted proxy: {err3}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
