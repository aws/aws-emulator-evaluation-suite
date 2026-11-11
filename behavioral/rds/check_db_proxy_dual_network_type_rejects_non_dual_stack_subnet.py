"""db-proxy-dual-network-type-rejects-non-dual-stack-subnet."""
from __future__ import annotations

import ipaddress
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "db-proxy-dual-network-type-rejects-non-dual-stack-subnet"
GROUP = 'proxy_network_type'
SERVICES = ['rds']

_MANAGED_TAGS = [
    {"Key": "sim2real:managed", "Value": "true"},
    {"Key": "sim2real:prefix", "Value": "sim2real-behav"},
]


def _two_azs(ctx):
    ec2 = ctx.client("ec2")
    azs = sorted(
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[{"Name": "state", "Values": ["available"]}]
        )["AvailabilityZones"]
    )
    assert len(azs) >= 2, f"region {ctx.region!r} offers fewer than 2 available AZs: {azs!r}"
    return azs[0], azs[1]


def _delete_vpc_tree(ec2, vpc_id, subnet_ids):
    for sid in subnet_ids:
        try:
            ec2.delete_subnet(SubnetId=sid)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "InvalidSubnetID.NotFound":
                raise
    try:
        ec2.delete_vpc(VpcId=vpc_id)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "InvalidVpcID.NotFound":
            raise


def _ipv4_only_vpc(ctx, az_a, az_b):
    """A VPC with no IPv6 CIDR at all, and two IPv4-only subnets in distinct AZs."""
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.231.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-rdsproxy-v4only-")}, *_MANAGED_TAGS]}
        ],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    subnet_a = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.231.1.0/24", AvailabilityZone=az_a)["Subnet"]["SubnetId"]
    subnet_b = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.231.2.0/24", AvailabilityZone=az_b)["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_vpc_tree(ec2, vpc_id, [subnet_a, subnet_b]))
    return vpc_id, subnet_a, subnet_b


def _wait_for_ipv6_cidr(ec2, vpc_id, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    while True:
        assocs = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0].get("Ipv6CidrBlockAssociationSet", [])
        for assoc in assocs:
            if assoc["Ipv6CidrBlockState"]["State"] == "associated":
                return assoc["Ipv6CidrBlock"]
        if time.monotonic() >= deadline:
            raise AssertionError(f"VPC {vpc_id} never reported an associated IPv6 CIDR within {timeout_s}s")
        time.sleep(interval_s)


def _dual_stack_vpc_with_mixed_subnets(ctx, az_a, az_b):
    """A VPC carrying an Amazon-provided /56 IPv6 CIDR, with:
      - two IPv4-only subnets (the VPC is dual-stack, the subnets are not), and
      - two dual-stack subnets, each carrying a derived /64 slice of the VPC's /56.
    Returns (vpc_id, non_dual_subnet_a, non_dual_subnet_b, dual_subnet_a, dual_subnet_b).
    """
    ec2 = ctx.client("ec2")
    vpc = ec2.create_vpc(
        CidrBlock="10.232.0.0/16",
        AmazonProvidedIpv6CidrBlock=True,
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name("sim2real-behav-rdsproxy-dual-")}, *_MANAGED_TAGS]}
        ],
    )["Vpc"]
    vpc_id = vpc["VpcId"]
    ipv6_cidr = _wait_for_ipv6_cidr(ec2, vpc_id)
    slices = list(ipaddress.ip_network(ipv6_cidr).subnets(new_prefix=64))
    assert len(slices) >= 4, f"VPC {vpc_id}'s IPv6 CIDR {ipv6_cidr} yielded only {len(slices)} /64 slices"

    non_dual_a = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.232.1.0/24", AvailabilityZone=az_a)["Subnet"]["SubnetId"]
    non_dual_b = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.232.2.0/24", AvailabilityZone=az_b)["Subnet"]["SubnetId"]
    dual_a = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.232.3.0/24", Ipv6CidrBlock=str(slices[2]), AvailabilityZone=az_a
    )["Subnet"]["SubnetId"]
    dual_b = ec2.create_subnet(
        VpcId=vpc_id, CidrBlock="10.232.4.0/24", Ipv6CidrBlock=str(slices[3]), AvailabilityZone=az_b
    )["Subnet"]["SubnetId"]
    ctx.on_cleanup(lambda: _delete_vpc_tree(ec2, vpc_id, [non_dual_a, non_dual_b, dual_a, dual_b]))
    return vpc_id, non_dual_a, non_dual_b, dual_a, dual_b


def _cleanup_role(iam, role_name):
    for pname in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
        iam.delete_role_policy(RoleName=role_name, PolicyName=pname)
    iam.delete_role(RoleName=role_name)


def _proxy_prerequisites(ctx):
    """IAM role + Secrets Manager secret a DB proxy's SECRETS auth needs. All teardown registered."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-proxyrole-")
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "rds.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
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
    sm = ctx.client("secretsmanager")
    secret = sm.create_secret(
        Name=ctx.unique_name("sim2real-behav-proxysecret-"),
        SecretString=json.dumps({"username": "sim2real", "password": "Sim2Real#ProxyPass99"}),
        Tags=_MANAGED_TAGS,
    )
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=secret["ARN"], ForceDeleteWithoutRecovery=True))
    return role["Role"]["Arn"], secret["ARN"]


def _create_db_proxy_outcome(rds, *, timeout_s: float = 90.0, interval_s: float = 5.0, **kwargs):
    """CreateDBProxy, retrying only role-propagation InvalidParameterValue errors.

    Returns (response_or_None, error_code_or_None, error_message_or_None)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return rds.create_db_proxy(**kwargs), None, None
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"]["Message"]
            if code == "InvalidParameterValue" and "role" in message.lower() and time.monotonic() < deadline:
                time.sleep(interval_s)
                continue
            return None, code, message


def _cleanup_proxy(rds, name, *, timeout_s=600.0, interval_s=10.0):
    """Delete the proxy and wait until it is gone: its ENIs sit in the check's subnets, so the VPC
    teardown registered before it cannot succeed while the proxy is still deleting."""
    try:
        rds.delete_db_proxy(DBProxyName=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "DBProxyNotFoundFault":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            rds.describe_db_proxies(DBProxyName=name)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "DBProxyNotFoundFault":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"proxy {name} still present {timeout_s}s after DeleteDBProxy")
        time.sleep(interval_s)


def _error_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError("expected call to fail but it succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateDBProxy(EndpointNetworkType=DUAL) rejects a non-dual-stack subnet with the same
    InvalidParameterCombination naming the subnet, in an IPv4-only or a dual-stack VPC, and leaves
    no proxy; dual-stack subnets are accepted and read back DUAL/IPV6.

    Reference: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/rds-proxy-network-prereqs.html
    """
    ec2 = ctx.client("ec2")
    rds = ctx.client("rds")
    az_a, az_b = _two_azs(ctx)

    v4_vpc, v4_subnet_a, v4_subnet_b = _ipv4_only_vpc(ctx, az_a, az_b)
    dual_vpc, mixed_a, mixed_b, dual_a, dual_b = _dual_stack_vpc_with_mixed_subnets(ctx, az_a, az_b)
    role_arn, secret_arn = _proxy_prerequisites(ctx)

    auth = [{"AuthScheme": "SECRETS", "SecretArn": secret_arn, "IAMAuth": "DISABLED"}]

    # Trigger 1: IPv4-only VPC -- neither subnet has an IPv6 CIDR.
    name_v4 = ctx.unique_name("sim2real-behav-proxy-v4only-")
    resp, code, message = _create_db_proxy_outcome(
        rds,
        DBProxyName=name_v4,
        EngineFamily="MYSQL",
        RoleArn=role_arn,
        VpcSubnetIds=[v4_subnet_a, v4_subnet_b],
        Auth=auth,
        EndpointNetworkType="DUAL",
    )
    assert resp is None, f"expected CreateDBProxy to reject an IPv4-only VPC under DUAL, got {resp!r}"
    # The refusal names the FIRST listed subnet that is not dual-stack.
    expected = ("InvalidParameterCombination", f"Subnet {v4_subnet_a} is not a dual stack subnet")
    assert (code, message) == expected, (
        f"IPv4-only VPC under DUAL (subnets a={v4_subnet_a}, b={v4_subnet_b}): expected "
        f"{expected!r}, got {(code, message)!r}"
    )

    # Trigger 2: dual-stack VPC, but THESE subnets were never given an IPv6 CIDR.
    name_mixed = ctx.unique_name("sim2real-behav-proxy-mixed-")
    resp, code, message = _create_db_proxy_outcome(
        rds,
        DBProxyName=name_mixed,
        EngineFamily="MYSQL",
        RoleArn=role_arn,
        VpcSubnetIds=[mixed_a, mixed_b],
        Auth=auth,
        EndpointNetworkType="DUAL",
    )
    assert resp is None, f"expected CreateDBProxy to reject non-dual-stack subnets in a dual-stack VPC, got {resp!r}"
    expected = ("InvalidParameterCombination", f"Subnet {mixed_a} is not a dual stack subnet")
    assert (code, message) == expected, (
        f"non-dual-stack subnets in a dual-stack VPC under DUAL (subnets a={mixed_a}, "
        f"b={mixed_b}): expected {expected!r}, got {(code, message)!r}"
    )

    # Effect absent: neither rejected name ever became a real proxy.
    for rejected_name in (name_v4, name_mixed):
        not_found_code = _error_code(lambda n=rejected_name: rds.describe_db_proxies(DBProxyName=n))
        assert not_found_code == "DBProxyNotFoundFault", (
            f"rejected proxy name {rejected_name!r} unexpectedly describes as something "
            f"({not_found_code!r}); CreateDBProxy must not have left a partial resource behind"
        )

    # Positive control: genuinely dual-stack subnets are accepted, and the network-type fields
    # round-trip through two independent DescribeDBProxies reads.
    name_dual = ctx.unique_name("sim2real-behav-proxy-dual-")
    resp, code, message = _create_db_proxy_outcome(
        rds,
        DBProxyName=name_dual,
        EngineFamily="MYSQL",
        RoleArn=role_arn,
        VpcSubnetIds=[dual_a, dual_b],
        Auth=auth,
        EndpointNetworkType="DUAL",
        TargetConnectionNetworkType="IPV6",
    )
    assert resp is not None, f"expected CreateDBProxy to accept dual-stack subnets under DUAL, got code={code!r} message={message!r}"
    ctx.on_cleanup(lambda: _cleanup_proxy(rds, name_dual))
    created = resp["DBProxy"]
    assert created["EndpointNetworkType"] == "DUAL", created
    assert created["TargetConnectionNetworkType"] == "IPV6", created

    for _ in range(2):
        described = rds.describe_db_proxies(DBProxyName=name_dual)["DBProxies"][0]
        assert described["EndpointNetworkType"] == "DUAL", described
        assert described["TargetConnectionNetworkType"] == "IPV6", described


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
