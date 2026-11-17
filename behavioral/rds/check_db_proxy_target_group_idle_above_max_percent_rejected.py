"""db-proxy-target-group-idle-above-max-percent-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "db-proxy-target-group-idle-above-max-percent-rejected"
GROUP = "proxy"
SERVICES = ["rds"]

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _default_db_subnet_ids(ctx, count=2):
    """Return *count* of the run's shared-network subnet ids in distinct AZs."""
    ec2 = ctx.client("ec2")
    subnets = ec2.describe_subnets(
        Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}]
    ).get("Subnets", [])
    by_az: dict[str, str] = {}
    for subnet in sorted(subnets, key=lambda s: s["SubnetId"]):
        by_az.setdefault(subnet["AvailabilityZone"], subnet["SubnetId"])
    ids = [by_az[az] for az in sorted(by_az)][:count]
    if len(ids) < count:
        raise AssertionError(f"shared network has only {len(ids)} usable subnets; need {count}")
    return ids


def _create_proxy_prerequisites(ctx):
    """Create the IAM role + Secrets Manager secret + 2-AZ subnets a DB proxy needs.

    Returns (role_arn, subnet_ids); all teardown is registered on ctx.
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

    def _delete_role():
        for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_teardown(_delete_role, "NoSuchEntity"))
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
        SecretString=json.dumps({"username": "sim2real", "password": "Sim2Real#Pass99"}),
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(
        _teardown(
            lambda: sm.delete_secret(SecretId=secret["ARN"], ForceDeleteWithoutRecovery=True),
            "ResourceNotFoundException",
        )
    )
    return role["Role"]["Arn"], subnet_ids


def _ensure_rds_service_linked_role(iam):
    """Create AWSServiceRoleForRDS if missing; an account that never used RDS lacks it and
    CreateDBProxy needs it."""
    try:
        iam.create_service_linked_role(AWSServiceName="rds.amazonaws.com")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidInput":
            raise


def _create_db_proxy_with_retry(rds, *, timeout_s=120, **kwargs):
    """CreateDBProxy can fail while the freshly-created IAM role, or the account's first-use
    RDS service-linked role, has not yet propagated; poll the real call (bounded) instead of a
    bare sleep."""
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            return rds.create_db_proxy(**kwargs)
        except Exception as exc:  # noqa: BLE001 - IAM/service-linked-role propagation, retry until the budget runs out
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"CreateDBProxy did not succeed within {timeout_s}s: {last_exc!r}")


def _wait_db_proxy_available(ctx, name, *, timeout_s=600):
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_proxies(DBProxyName=name)["DBProxies"][0]["Status"]
        if last == "available":
            return
        time.sleep(2)
    raise AssertionError(f"DB proxy {name} did not reach 'available' within {timeout_s}s, last status {last!r}")


def _wait_target_group_pool(ctx, name, *, max_connections_percent, max_idle_connections_percent,
                             connection_borrow_timeout, timeout_s=180):
    """An independent DescribeDBProxyTargetGroups read confirming a settled pool config, not
    just that the mutating call's own response echoed it back."""
    rds = ctx.client("rds")
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = rds.describe_db_proxy_target_groups(DBProxyName=name, TargetGroupName="default")[
            "TargetGroups"
        ][0]
        pool = last["ConnectionPoolConfig"]
        if (
            pool["MaxConnectionsPercent"] == max_connections_percent
            and pool["MaxIdleConnectionsPercent"] == max_idle_connections_percent
            and pool["ConnectionBorrowTimeout"] == connection_borrow_timeout
        ):
            return last
        time.sleep(2)
    raise AssertionError(
        f"target group pool config for {name} not observed within {timeout_s}s, last={last}"
    )


def _error(fn):
    """The Error.Code and Error.Message ``fn`` raises. An unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyDBProxyTargetGroup with MaxIdleConnectionsPercent over MaxConnectionsPercent is
    refused with InvalidParameterCombination, and the prior pool config is unchanged.
    """
    rds = ctx.client("rds")
    _ensure_rds_service_linked_role(ctx.client("iam"))
    role_arn, subnet_ids = _create_proxy_prerequisites(ctx)
    name = ctx.unique_name("sim2real-behav-proxy-")
    _create_db_proxy_with_retry(
        rds,
        DBProxyName=name,
        EngineFamily="MYSQL",
        RoleArn=role_arn,
        VpcSubnetIds=subnet_ids,
        DefaultAuthScheme="IAM_AUTH",
    )
    ctx.on_cleanup(_teardown(lambda: rds.delete_db_proxy(DBProxyName=name), "DBProxyNotFoundFault"))
    _wait_db_proxy_available(ctx, name)

    # Establish a known-good pool config: the positive control the refusal is measured against.
    rds.modify_db_proxy_target_group(
        DBProxyName=name,
        TargetGroupName="default",
        ConnectionPoolConfig={
            "MaxConnectionsPercent": 73,
            "MaxIdleConnectionsPercent": 41,
            "ConnectionBorrowTimeout": 37,
            "InitQuery": "SET sql_mode='STRICT_ALL_TABLES'",
            "SessionPinningFilters": ["EXCLUDE_VARIABLE_SETS"],
        },
    )
    baseline = _wait_target_group_pool(
        ctx, name, max_connections_percent=73, max_idle_connections_percent=41,
        connection_borrow_timeout=37,
    )
    baseline_pool = baseline["ConnectionPoolConfig"]
    assert baseline_pool["InitQuery"] == "SET sql_mode='STRICT_ALL_TABLES'", baseline_pool
    assert baseline_pool["SessionPinningFilters"] == ["EXCLUDE_VARIABLE_SETS"], baseline_pool

    # The refusal neighbour: MaxIdleConnectionsPercent (80) above MaxConnectionsPercent (73),
    # also attempting to change every other pool field so an atomic refusal is provable.
    code, message = _error(
        lambda: rds.modify_db_proxy_target_group(
            DBProxyName=name,
            TargetGroupName="default",
            ConnectionPoolConfig={
                "MaxConnectionsPercent": 73,
                "MaxIdleConnectionsPercent": 80,
                "ConnectionBorrowTimeout": 99,
                "InitQuery": "SET sql_mode=''",
                "SessionPinningFilters": [],
            },
        )
    )
    assert code == "InvalidParameterCombination", f"unexpected error code {code!r}: {message!r}"
    assert message == "MaxConnectionsPercent 73 must be greater than MaxIdleConnectionsPercent 80", (
        f"unexpected error message: {message!r}"
    )

    unchanged = rds.describe_db_proxy_target_groups(DBProxyName=name, TargetGroupName="default")[
        "TargetGroups"
    ][0]["ConnectionPoolConfig"]
    assert unchanged["MaxConnectionsPercent"] == 73, unchanged
    assert unchanged["MaxIdleConnectionsPercent"] == 41, unchanged
    assert unchanged["ConnectionBorrowTimeout"] == 37, unchanged
    assert unchanged["InitQuery"] == "SET sql_mode='STRICT_ALL_TABLES'", unchanged
    assert unchanged["SessionPinningFilters"] == ["EXCLUDE_VARIABLE_SETS"], unchanged


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
