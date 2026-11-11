"""encryption-config-key-arn-byte-preserved."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "encryption-config-key-arn-byte-preserved"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """The KMS key ARN supplied in encryption config is stored/returned exactly, with no normalization or truncation."""
    eks = ctx.client("eks")
    kms = ctx.client("kms")
    iam = ctx.client("iam")
    cluster = _create_active_cluster(ctx)
    name = cluster["name"]
    role_name = cluster["roleArn"].rsplit("/", 1)[-1]

    key = kms.create_key(Description=ctx.unique_name("sim2real-eks-kms-"))["KeyMetadata"]
    key_arn = key["Arn"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key["KeyId"], PendingWindowInDays=7))

    # AmazonEKSClusterPolicy grants no kms:* actions, so without this the cluster
    # role cannot call kms:CreateGrant/DescribeKey and AssociateEncryptionConfig fails.
    policy_name = "sim2real-eks-kms-access"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=policy_name,
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        "Effect": "Allow",
                        "Action": ["kms:Encrypt", "kms:Decrypt", "kms:DescribeKey", "kms:CreateGrant"],
                        "Resource": key_arn,
                    }
                ],
            }
        ),
    )
    ctx.on_cleanup(lambda: iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name))

    update_id = _associate_encryption_config_with_retry(eks, name, key_arn)
    _wait_for_update(ctx, name, update_id)

    described = eks.describe_cluster(name=name)["cluster"]
    enc_config = described["encryptionConfig"]
    assert len(enc_config) == 1, f"expected exactly one encryptionConfig entry, got {enc_config!r}"
    assert enc_config[0]["resources"] == ["secrets"], (
        f"expected resources == ['secrets'], got {enc_config[0]['resources']!r}"
    )
    assert enc_config[0]["provider"]["keyArn"] == key_arn, (
        f"keyArn mutated: {enc_config[0]['provider']['keyArn']!r} != {key_arn!r}"
    )

    # A second, independent read must return the identical bytes, not a re-derived ARN.
    described_again = eks.describe_cluster(name=name)["cluster"]
    again_arn = described_again["encryptionConfig"][0]["provider"]["keyArn"]
    assert again_arn == key_arn, f"keyArn changed across reads: {again_arn!r} != {key_arn!r}"


def _get_two_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if vpcs:
        vpc_id = vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az: dict[str, str] = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        if len(by_az) >= 2:
            return list(by_az.values())[:3]

    # No usable shared network (a freshly-provisioned account may not have one) --
    # create a minimal 2-AZ VPC rather than depending on ambient state.
    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: ec2.delete_vpc(VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-vpc-")}])
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ][:2]
    if len(azs) < 2:
        raise AssertionError("region does not have >=2 available availability zones for an EKS cluster")
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.42.{i}.0/24", AvailabilityZone=az)["Subnet"][
            "SubnetId"
        ]
        ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-eks-subnet-")}])
        ctx.on_cleanup(lambda sid=subnet_id: ec2.delete_subnet(SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))["Role"]
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
    for _ in range(10):
        try:
            iam.get_role(RoleName=role_name)
            break
        except Exception:
            time.sleep(2)
    return role["Arn"]


def _wait_for_cluster_active(ctx, name, timeout_s=1200.0, interval_s=20.0):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        cluster = eks.describe_cluster(name=name)["cluster"]
        status = cluster["status"]
        if status == "ACTIVE":
            return cluster
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED status while waiting for ACTIVE")
        time.sleep(interval_s)
    raise AssertionError(f"cluster {name} did not reach ACTIVE within {timeout_s}s")


def _delete_cluster_safe(ctx, name):
    eks = ctx.client("eks")
    deadline = time.monotonic() + 300.0
    while time.monotonic() < deadline:
        try:
            status = eks.describe_cluster(name=name)["cluster"]["status"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        if status not in ("CREATING", "UPDATING", "DELETING"):
            break
        time.sleep(15)
    _delete_eks_cluster_retrying(eks, name)


def _create_active_cluster(ctx, **extra_kwargs):
    eks = ctx.client("eks")
    subnets = _get_two_az_subnets(ctx)
    role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-")
    kwargs = dict(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnets})
    kwargs.update(extra_kwargs)

    deadline = time.monotonic() + 90.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(**kwargs)
            break
        except Exception as exc:  # a freshly-created IAM role can take a few seconds to propagate
            last_exc = exc
            time.sleep(5)
    else:
        raise last_exc

    ctx.on_cleanup(lambda: _delete_cluster_safe(ctx, name))
    return _wait_for_cluster_active(ctx, name)


def _associate_encryption_config_with_retry(eks, name, key_arn, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = eks.associate_encryption_config(
                clusterName=name,
                encryptionConfig=[{"resources": ["secrets"], "provider": {"keyArn": key_arn}}],
            )
            return resp["update"]["id"]
        except Exception as exc:  # a freshly-granted IAM role policy can take a few seconds to propagate
            last_exc = exc
            time.sleep(5)
    raise last_exc


def _wait_for_update(ctx, cluster_name, update_id, timeout_s=2700.0, interval_s=15.0):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        update = eks.describe_update(name=cluster_name, updateId=update_id)["update"]
        status = update["status"]
        if status != "InProgress":
            if status != "Successful":
                raise AssertionError(f"update {update_id} ended in {status}: {update.get('errors')}")
            return update
        time.sleep(interval_s)
    raise AssertionError(f"update {update_id} did not complete within {timeout_s}s")



def _delete_eks_cluster_retrying(eks, name, timeout_s=900.0, interval_s=20.0):
    """DeleteCluster, retried while EKS refuses it because an update or child resource is in flight."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return eks.delete_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return None
            if e.response["Error"]["Code"] != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
