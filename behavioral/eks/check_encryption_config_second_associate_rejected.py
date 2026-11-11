"""encryption-config-second-associate-rejected."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "encryption-config-second-associate-rejected"
GROUP = "representation"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A cluster encrypted at create rejects a second AssociateEncryptionConfig.

    The refusal is InvalidParameterException with the exact message; the original keyArn is kept.
    """
    eks = ctx.client("eks")
    prereqs = _setup_network_and_role(ctx)
    key_arn_1 = _setup_kms_key_for_role(ctx, prereqs["role_name"], "one")
    key_arn_2 = _setup_kms_key_for_role(ctx, prereqs["role_name"], "two")
    name = ctx.unique_name("sim2real-eks-encneg-")

    cluster = _create_active_cluster_with_retry(
        ctx,
        eks,
        name,
        prereqs["role_arn"],
        prereqs["subnet_ids"],
        encryptionConfig=[{"resources": ["secrets"], "provider": {"keyArn": key_arn_1}}],
    )

    # positive control: encryption was applied at create time with the first key
    assert cluster["encryptionConfig"][0]["provider"]["keyArn"] == key_arn_1, (
        f"expected create-time key {key_arn_1}, got {cluster['encryptionConfig']}"
    )

    code, message = _error_detail(
        lambda: eks.associate_encryption_config(
            clusterName=name,
            encryptionConfig=[{"resources": ["secrets"], "provider": {"keyArn": key_arn_2}}],
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}: {message!r}"
    expected_message = "Encryption is already enabled on the cluster"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    described = eks.describe_cluster(name=name)["cluster"]
    assert len(described["encryptionConfig"]) == 1, (
        f"expected exactly one encryption config after rejected associate, got {described['encryptionConfig']}"
    )
    assert described["encryptionConfig"][0]["provider"]["keyArn"] == key_arn_1, (
        f"expected original key {key_arn_1} untouched, got {described['encryptionConfig'][0]['provider']['keyArn']}"
    )


def _error_detail(fn):
    """Call fn(); return its botocore error (code, message). An unexpected success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


def _setup_kms_key_for_role(ctx, role_name, suffix):
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    key = kms.create_key(Description=ctx.unique_name(f"sim2real-eks-kms-{suffix}-"))["KeyMetadata"]
    key_id, key_arn = key["KeyId"], key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))
    policy_name = f"sim2real-eks-kms-access-{suffix}"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": [
                            "kms:Encrypt",
                            "kms:Decrypt",
                            "kms:DescribeKey",
                            "kms:CreateGrant",
                            "kms:GenerateDataKey*",
                        ],
                        "Resource": key_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))
    return key_arn


def _get_or_create_subnets(ctx, ec2):
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        subnet_ids = list(by_az.values())[:2]
        if len(subnet_ids) >= 2:
            return vpc_id, subnet_ids
    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}])
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.42.{i}.0/24", AvailabilityZone=az)["Subnet"][
            "SubnetId"
        ]
        ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-subnet-")}])
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return vpc_id, subnet_ids


def _setup_network_and_role(ctx):
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    vpc_id, subnet_ids = _get_or_create_subnets(ctx, ec2)
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup_role():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        finally:
            iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)
    return {"vpc_id": vpc_id, "subnet_ids": subnet_ids, "role_arn": role_arn, "role_name": role_name}


def _create_active_cluster_with_retry(ctx, eks, name, role_arn, subnet_ids, timeout_s=1500, **extra):
    deadline = time.monotonic() + 120
    resp = None
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = eks.create_cluster(
                name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids}, **extra
            )
            break
        except Exception as exc:
            # fresh IAM role/key-policy grants can take a few seconds to propagate
            last_exc = exc
            time.sleep(5)
    if resp is None:
        raise last_exc

    def _cleanup_cluster():
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_cluster)
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        desc = eks.describe_cluster(name=name)["cluster"]
        if desc["status"] == "ACTIVE":
            return desc
        if desc["status"] == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED status")
        time.sleep(2)
    raise AssertionError(f"cluster {name} did not reach ACTIVE within {timeout_s}s")


# A cluster, load balancer, endpoint or instance in this VPC deletes asynchronously: its ENIs linger
# in the subnet / security group, so an immediate DeleteSubnet / DeleteSecurityGroup / DeleteVpc fails
# with DependencyViolation. Wait (bounded) for the ENIs to go, retry DependencyViolation in the same
# window, then raise naming the ENIs still attached. One window is shared by a check's network deletes.
_NET_TEARDOWN_S = 1260.0
_NET_ENI_FILTER = {"VpcId": "vpc-id", "SubnetId": "subnet-id", "GroupId": "group-id"}
_NET_DEADLINES: dict = {}


def _delete_net(client, op, **ident):
    import time as _time

    from botocore.exceptions import ClientError as _ClientError

    held = _NET_DEADLINES.get(id(client))
    if held is None or held[0] is not client:
        held = _NET_DEADLINES[id(client)] = (client, _time.monotonic() + _NET_TEARDOWN_S)
    deadline = held[1]
    flt = [{"Name": _NET_ENI_FILTER[k], "Values": [v]} for k, v in ident.items() if k in _NET_ENI_FILTER]
    while _net_enis(client, flt) and _time.monotonic() < deadline:
        _time.sleep(10)
    while True:
        try:
            return getattr(client, op)(**ident)
        except _ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code != "DependencyViolation":
                raise
            if _time.monotonic() >= deadline:
                # Same exception type and code, so a caller catching ClientError still collects it.
                raise type(exc)(
                    {**exc.response, "Error": {**exc.response.get("Error", {}), "Message": (
                        f"{op}({ident}): DependencyViolation after {_NET_TEARDOWN_S}s; "
                        f"ENIs still attached: {_net_enis(client, flt)}"
                    )}},
                    exc.operation_name,
                ) from exc
        _time.sleep(10)


def _net_enis(client, flt):
    from botocore.exceptions import ClientError as _ClientError

    if not flt:
        return []
    try:
        enis = client.describe_network_interfaces(Filters=flt)["NetworkInterfaces"]
    except _ClientError:
        return []  # a diagnostic only: the delete itself still reports its own failure
    return [f"{e['NetworkInterfaceId']}:{e.get('InterfaceType') or e.get('Description', '')[:40]}" for e in enis]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
