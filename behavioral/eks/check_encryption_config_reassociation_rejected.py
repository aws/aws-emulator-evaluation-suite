"""encryption-config-reassociation-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "encryption-config-reassociation-rejected"
GROUP = "state-machine"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A second AssociateEncryptionConfig on a cluster whose secrets are encrypted with one key is rejected with
    InvalidParameterException "Encryption is already enabled on the cluster", and the cluster keeps exactly the
    first key's encryptionConfig."""
    eks = ctx.client("eks")
    kms = ctx.client("kms")
    cluster, role_name = _create_active_cluster(ctx)
    name = cluster["name"]

    key_tags = [{"TagKey": "sim2real", "TagValue": "true"}]
    key1 = kms.create_key(Description=ctx.unique_name("sim2real-eks-kms-a-"), Tags=key_tags)["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key1["KeyId"], PendingWindowInDays=7))
    key2 = kms.create_key(Description=ctx.unique_name("sim2real-eks-kms-b-"), Tags=key_tags)["KeyMetadata"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key2["KeyId"], PendingWindowInDays=7))

    # The cluster's own role must be able to use the key, or AssociateEncryptionConfig
    # never leaves InProgress: EKS re-encrypts secrets using the cluster role's grant.
    _grant_kms_access(ctx, role_name, key1["Arn"])

    # Positive control: the first association must succeed.
    update = eks.associate_encryption_config(
        clusterName=name,
        encryptionConfig=[{"resources": ["secrets"], "provider": {"keyArn": key1["Arn"]}}],
    )["update"]
    _wait_for_update(ctx, name, update["id"])
    described = eks.describe_cluster(name=name)["cluster"]
    assert described["encryptionConfig"][0]["provider"]["keyArn"] == key1["Arn"], (
        f"expected positive control to associate {key1['Arn']!r}, "
        f"got {described['encryptionConfig']!r}"
    )

    # Break exactly one thing: attempt to associate a second encryption config on the same cluster.
    code, message = _error_detail(
        lambda: eks.associate_encryption_config(
            clusterName=name,
            encryptionConfig=[{"resources": ["secrets"], "provider": {"keyArn": key2["Arn"]}}],
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}: {message}"
    expected_message = "Encryption is already enabled on the cluster"
    assert message == expected_message, (
        f"expected the rejection message {expected_message!r}, got {message!r}"
    )

    # Effect absent: the cluster's encryption config still points at the original key only.
    described_after = eks.describe_cluster(name=name)["cluster"]
    enc_config = described_after["encryptionConfig"]
    assert len(enc_config) == 1, f"expected exactly one encryptionConfig entry, got {enc_config!r}"
    assert enc_config[0]["provider"]["keyArn"] == key1["Arn"], "second key must not have been applied"


def _error_detail(fn):
    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected the call to be rejected, but it succeeded")


def _grant_kms_access(ctx, role_name, key_arn):
    iam = ctx.client("iam")
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


def _get_two_az_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:
        raise AssertionError("no shared network VPC available to provision the EKS cluster prerequisite subnets")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    by_az: dict[str, str] = {}
    for s in subnets:
        by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError("shared network does not have subnets in >=2 availability zones for an EKS cluster")
    return list(by_az.values())[:3]


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]
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
    return role_name, role["Arn"]


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


# Inside the 1800 s eks cleanup budget.
_TEARDOWN_S = 1680.0


def _delete_cluster_safe(ctx, name):
    """Delete the cluster once it leaves CREATING or UPDATING and wait every 2 s until it is gone.
    DeleteCluster answers ResourceInUseException while an update is in flight, which is retried;
    any other failure, or the deadline passing, raises."""
    eks = ctx.client("eks")
    deadline = time.monotonic() + _TEARDOWN_S
    status = None
    while True:
        try:
            status = eks.describe_cluster(name=name)["cluster"]["status"]
            if status not in ("CREATING", "UPDATING", "DELETING"):
                eks.delete_cluster(name=name)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException":
                raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"cluster {name} still {status!r} at the teardown deadline")
        time.sleep(2)


def _create_active_cluster(ctx, **extra_kwargs):
    eks = ctx.client("eks")
    subnets = _get_two_az_subnets(ctx)
    role_name, role_arn = _create_cluster_role(ctx)
    name = ctx.unique_name("sim2real-eks-")
    kwargs = dict(
        name=name,
        roleArn=role_arn,
        resourcesVpcConfig={"subnetIds": subnets},
        tags={"sim2real": "true"},
    )
    kwargs.update(extra_kwargs)

    # CreateCluster answers InvalidParameterException until the new role propagates to EKS.
    left = ctx.time_left()
    deadline = time.monotonic() + min(120.0, 120.0 if left is None else left)
    while True:
        try:
            eks.create_cluster(**kwargs)
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException" or time.monotonic() >= deadline:
                raise
        time.sleep(2)

    ctx.on_cleanup(lambda: _delete_cluster_safe(ctx, name))
    return _wait_for_cluster_active(ctx, name), role_name


def _wait_for_update(ctx, cluster_name, update_id, timeout_s=2400.0, interval_s=15.0):
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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
