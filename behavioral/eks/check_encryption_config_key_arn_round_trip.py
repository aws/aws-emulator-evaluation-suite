"""encryption-config-key-arn-round-trip."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "encryption-config-key-arn-round-trip"
GROUP = "representation"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A KMS key ARN supplied to AssociateEncryptionConfig persists character-for-character
    unchanged on DescribeCluster, across repeated reads, once the update completes."""
    eks = ctx.client("eks")
    cluster = _create_active_cluster(ctx)
    key_arn = _create_kms_key_for_role(ctx, cluster["role_arn"])

    resp = eks.associate_encryption_config(
        clusterName=cluster["name"],
        encryptionConfig=[{"provider": {"keyArn": key_arn}, "resources": ["secrets"]}],
    )
    update_id = resp["update"]["id"]

    update = _poll_until(
        lambda: eks.describe_update(name=cluster["name"], updateId=update_id)["update"],
        lambda u: u["status"] in ("Successful", "Failed", "Cancelled"),
        timeout_s=2700.0,
        interval_s=20.0,
    )
    assert update["status"] == "Successful", f"encryption config update ended as {update['status']}: {update.get('errors')}"

    desc1 = eks.describe_cluster(name=cluster["name"])["cluster"]
    stored_arn_1 = desc1["encryptionConfig"][0]["provider"]["keyArn"]
    assert stored_arn_1 == key_arn, f"stored keyArn {stored_arn_1!r} != supplied {key_arn!r}"

    # Repeated read must return the exact same characters, not a re-normalized ARN.
    desc2 = eks.describe_cluster(name=cluster["name"])["cluster"]
    stored_arn_2 = desc2["encryptionConfig"][0]["provider"]["keyArn"]
    assert stored_arn_2 == key_arn, f"second read keyArn {stored_arn_2!r} != supplied {key_arn!r}"
    assert stored_arn_2 == stored_arn_1, f"keyArn changed between reads: {stored_arn_1!r} -> {stored_arn_2!r}"


def _get_two_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return list(by_az.values())[:2]

    # No usable shared network (a freshly provisioned account may not have one) — provision our own.
    vpc_id = ec2.create_vpc(CidrBlock="10.43.0.0/16")["Vpc"]["VpcId"]
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}])
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region has fewer than two available availability zones required by EKS")
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.43.{i}.0/24", AvailabilityZone=az)["Subnet"][
            "SubnetId"
        ]
        ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-subnet-")}])
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return iam.get_role(RoleName=role_name)["Role"]["Arn"]


def _poll_until(probe, predicate, timeout_s=1200.0, interval_s=15.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {last!r})")


def _wait_cluster_status(ctx, name, statuses, timeout_s=1200.0, interval_s=15.0):
    eks = ctx.client("eks")
    return _poll_until(
        lambda: eks.describe_cluster(name=name)["cluster"],
        lambda c: c["status"] in statuses,
        timeout_s=timeout_s,
        interval_s=interval_s,
    )


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    name = ctx.unique_name("sim2real-eks-")
    subnets = _get_two_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    eks.create_cluster(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnets},
        tags={"sim2real-check": CHECK},
    )

    def _cleanup():
        try:
            _wait_cluster_status(ctx, name, {"ACTIVE", "FAILED"}, timeout_s=1200.0)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
        deadline = time.monotonic() + 900.0
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
                break
            time.sleep(15.0)

    ctx.on_cleanup(_cleanup)
    desc = _wait_cluster_status(ctx, name, {"ACTIVE", "FAILED"}, timeout_s=1200.0)
    if desc["status"] != "ACTIVE":
        raise AssertionError(f"cluster {name} entered status {desc['status']} instead of ACTIVE")
    return {"name": name, "arn": desc["arn"], "role_arn": role_arn, "subnets": subnets}


def _create_kms_key_for_role(ctx, role_arn):
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowRootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "AllowEksClusterRoleToUseKey",
                "Effect": "Allow",
                "Principal": {"AWS": role_arn},
                "Action": ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey", "kms:CreateGrant"],
                "Resource": "*",
            },
        ],
    }
    resp = kms.create_key(
        Description=ctx.unique_name("sim2real-eks-enc-"),
        KeyUsage="ENCRYPT_DECRYPT",
        Policy=json.dumps(policy),
        Tags=[{"TagKey": "sim2real-check", "TagValue": CHECK}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    key_arn = resp["KeyMetadata"]["Arn"]

    def _cleanup():
        try:
            kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)
    return key_arn


# EC2 network teardown waits for AWS-managed ENIs to leave before it deletes. A load balancer,
# directory, endpoint, cluster, function or instance in this VPC deletes ASYNCHRONOUSLY: its delete
# returns while its ENIs still sit in the subnet / security group, so an immediate DeleteSubnet /
# DeleteSecurityGroup / DeleteVpc fails with DependencyViolation -- and swallowing that leaks the VPC
# while the check passes, until the account's VPC quota fails later checks. So wait
# (bounded) for the resource's ENIs to go, retry DependencyViolation inside the same window, and raise
# a final failure naming the ENIs still attached. Every other error propagates.
# Teardown-only: nothing run() executes calls this, so it cannot change the verdict. The window is
# shared by all of one check's network deletes and fits the suite's 1800 s cleanup budget.
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
