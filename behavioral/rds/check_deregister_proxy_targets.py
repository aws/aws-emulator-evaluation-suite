"""deregister-proxy-targets."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError


from behavioral_harness import tags

CHECK = "deregister-proxy-targets"
GROUP = 'proxy'
SERVICES = ['rds']

ERR_PROXY_NOT_FOUND = "DBProxyNotFoundFault"

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _error_code(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError(f"expected a ClientError rejection, but the call SUCCEEDED and returned {result!r}")


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
    """Return *count* shared-network subnet ids in distinct AZs."""
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
        SecretString=json.dumps({"username": "sim2real", "password": "Sim2Real#Pass99"}),
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(
        lambda: sm.delete_secret(SecretId=secret["ARN"], ForceDeleteWithoutRecovery=True)
    )
    return role["Role"]["Arn"], secret["ARN"], subnet_ids


def _create_db_proxy_with_retry(rds, *, timeout_s=90.0, interval_s=10.0, **kwargs):
    """Create the proxy, retrying InvalidParameterValue while the new IAM role's trust policy
    propagates to RDS."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rds.create_db_proxy(**kwargs)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "InvalidParameterValue" and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            raise


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterDBProxyTargets on an unknown proxy fails DBProxyNotFoundFault.

    A registered DB instance appears in DescribeDBProxyTargets and disappears once deregistered.
    """
    rds = ctx.client("rds")
    bogus_proxy = ctx.unique_name("sim2real-behav-proxy-missing-")
    code, message = _error_code(
        lambda: rds.deregister_db_proxy_targets(
            DBProxyName=bogus_proxy,
            DBInstanceIdentifiers=[ctx.unique_name("sim2real-behav-dbi-missing-")],
        )
    )
    assert code == ERR_PROXY_NOT_FOUND, f"unexpected error code: {code}"
    assert message == f"DBProxy '{bogus_proxy}' not found.", message


    role_arn, secret_arn, subnet_ids = _create_proxy_prerequisites(ctx)

    proxy_name = ctx.unique_name("sim2real-behav-proxy-")
    _create_db_proxy_with_retry(
        rds,
        DBProxyName=proxy_name,
        EngineFamily="MYSQL",
        RoleArn=role_arn,
        VpcSubnetIds=subnet_ids,
        Auth=[{"AuthScheme": "SECRETS", "SecretArn": secret_arn, "IAMAuth": "DISABLED"}],
    )
    ctx.on_cleanup(lambda: rds.delete_db_proxy(DBProxyName=proxy_name))
    _poll_until(
        lambda: (rds.describe_db_proxies(DBProxyName=proxy_name).get("DBProxies") or [None])[0],
        lambda p: p is not None and p.get("Status") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"db proxy {proxy_name} available",
    )

    ident = ctx.unique_name("sim2real-behav-dbi-")
    subnet_group = _network_db_subnet_group(ctx, rds)
    rds.create_db_instance(
        DBInstanceIdentifier=ident,
        DBInstanceClass="db.t3.micro",
        Engine="mysql",
        MasterUsername="admin",
        MasterUserPassword="Sim2Real#Pass99",
        AllocatedStorage=20,
        BackupRetentionPeriod=1,
        MultiAZ=False,
        PubliclyAccessible=False,
        StorageType="gp2",
        DBSubnetGroupName=subnet_group,
    )
    ctx.on_cleanup(lambda: rds.delete_db_instance(
        DBInstanceIdentifier=ident, SkipFinalSnapshot=True, DeleteAutomatedBackups=True))
    _poll_until(
        lambda: rds.describe_db_instances(DBInstanceIdentifier=ident)["DBInstances"][0],
        lambda i: i.get("DBInstanceStatus") == "available",
        timeout_s=900,
        interval_s=10,
        description=f"instance {ident} available",
    )

    rds.register_db_proxy_targets(DBProxyName=proxy_name, DBInstanceIdentifiers=[ident])

    def targets_include_instance():
        targets = rds.describe_db_proxy_targets(DBProxyName=proxy_name).get("Targets", [])
        return any(t.get("RdsResourceId") == ident for t in targets)

    _poll_until(
        targets_include_instance,
        lambda present: present,
        timeout_s=180,
        interval_s=5,
        description=f"proxy target {ident} registered",
    )

    rds.deregister_db_proxy_targets(DBProxyName=proxy_name, DBInstanceIdentifiers=[ident])
    _poll_until(
        targets_include_instance,
        lambda present: not present,
        timeout_s=180,
        interval_s=5,
        description=f"proxy target {ident} deregistered",
    )


def _network_db_subnet_group(ctx, client) -> str:
    """A DB subnet group over the run's shared network, deleted once nothing uses it."""
    name = ctx.unique_name("sim2real-net-dbsg-")
    client.create_db_subnet_group(
        DBSubnetGroupName=name,
        DBSubnetGroupDescription="sim2real shared network",
        SubnetIds=ctx.network().subnet_ids,
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(
        lambda: _delete_when_released(
            lambda: client.delete_db_subnet_group(DBSubnetGroupName=name),
            ("InvalidDBSubnetGroupStateFault", "InvalidDBSubnetGroupState"),
            ("DBSubnetGroupNotFoundFault",),
        )
    )
    return name


def _delete_when_released(delete, busy_codes, gone_codes, timeout_s=1500.0, interval_s=15.0):
    """Delete a subnet group, retrying while a resource that is being deleted still uses it."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            delete()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in gone_codes:
                return
            if code not in busy_codes or time.monotonic() >= deadline:
                raise
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
