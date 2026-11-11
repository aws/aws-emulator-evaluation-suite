"""encryption-config-association-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "encryption-config-association-lifecycle"
GROUP = 'data-plane'
SERVICES = ['eks']

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _error_detail(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _trust(service, extra_actions=()):
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": service},
                    "Action": ["sts:AssumeRole", *extra_actions],
                }
            ],
        }
    )


def _ensure_role(ctx, name, service="eks.amazonaws.com", managed_policies=()):
    """Create-or-reuse an IAM role and return its ARN."""
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service),
            Description="SimParityProbe EKS behavioral fidelity fixture",
            Tags=[{"Key": "sim2real:managed", "Value": "true"}],
        )["Role"]["Arn"]
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "EntityAlreadyExists":
            arn = iam.get_role(RoleName=name)["Role"]["Arn"]
        elif code in ("AccessDenied", "AccessDeniedException"):
            raise AssertionError(f"probe identity cannot create IAM role {name}: {exc}") from exc
        else:
            raise
    for policy_arn in managed_policies:
        try:
            iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError:
            pass
    return arn


def _principal_role(ctx, label="eks-principal-"):
    """A fresh, IAM-propagated throwaway principal EKS will accept."""
    return _ensure_role(ctx, ctx.unique_name(PREFIX + label), "ec2.amazonaws.com")


def _subnet_ids(ctx):
    """Two subnets in two distinct, EKS-supported AZs of the shared network."""
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    if not subnets:
        raise AssertionError(f"the run's shared network subnets {ctx.network().subnet_ids} are not visible")
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        az = sn["AvailabilityZone"]
        if sn["AvailabilityZoneId"] in _BAD_AZS:
            continue
        by_az.setdefault(az, sn["SubnetId"])
    if len(by_az) < 2:
        raise AssertionError(f"need subnets in >=2 EKS-supported AZs, found {len(by_az)}")
    return [by_az[az] for az in sorted(by_az)][:2]


def _wait_for(fn, pred, timeout_s=300, interval_s=5, desc=""):
    deadline = time.time() + timeout_s
    while True:
        last = fn()
        if pred(last):
            return last
        if time.time() >= deadline:
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last!r}")
        time.sleep(interval_s)


def _active_cluster(ctx, c, suffix):
    """Provision (create + wait ACTIVE) a throwaway cluster, register cleanup, return its name."""
    role_arn = _ensure_role(ctx, CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    name = ctx.unique_name(PREFIX + suffix)
    deadline = time.monotonic() + 90
    while True:
        try:
            c.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={
                    "subnetIds": _subnet_ids(ctx),
                    "endpointPublicAccess": True,
                    "endpointPrivateAccess": False,
                },
                accessConfig={
                    "authenticationMode": "API_AND_CONFIG_MAP",
                    "bootstrapClusterCreatorAdminPermissions": True,
                },
                tags={"sim2real": "1"},
            )
            break
        except ClientError as exc:
            # a brand-new IAM role is eventually consistent: EKS rejects it until it propagates.
            if time.monotonic() >= deadline:
                raise AssertionError(f"create_cluster for {name} never accepted role {role_arn}: {exc}") from exc
            time.sleep(5)
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(c, name))
    resp = _wait_for(
        lambda: c.describe_cluster(name=name),
        lambda r: r["cluster"]["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1500,
        interval_s=20,
        desc=f"cluster {name} status==ACTIVE",
    )
    cluster = resp["cluster"]
    assert cluster["status"] == "ACTIVE", f"cluster {name} landed in {cluster['status']!r}"
    return name

import uuid


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """AssociateEncryptionConfig rejects an unknown cluster and a malformed key ARN, and DescribeUpdate an
    unknown update id, each with its exact code and message; the ACTIVE cluster keeps no encryptionConfig
    and gains no update (the association is irreversible, so the check never makes it)."""
    c = ctx.client("eks")
    name = _active_cluster(ctx, c, "eks-enc-")
    cluster = c.describe_cluster(name=name)["cluster"]
    assert not cluster.get("encryptionConfig"), cluster.get("encryptionConfig")
    before = set(c.list_updates(name=name)["updateIds"])

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    plausible = f"arn:aws:kms:{ctx.region}:{account_id}:key/{uuid.uuid4()}"
    absent_name = ctx.unique_name("absent-clu-")
    absent_code, absent_message = _error_detail(
        lambda: c.associate_encryption_config(
            clusterName=absent_name,
            encryptionConfig=[{"resources": ["secrets"], "provider": {"keyArn": plausible}}],
        )
    )
    assert absent_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {absent_code!r}"
    expected = f"No cluster found for name: {absent_name}."
    assert absent_message == expected, f"expected message {expected!r}, got {absent_message!r}"

    bad_arn_code, bad_arn_message = _error_detail(
        lambda: c.associate_encryption_config(
            clusterName=name,
            encryptionConfig=[{"resources": ["secrets"], "provider": {"keyArn": "not-a-kms-arn"}}],
        )
    )
    assert bad_arn_code == "InvalidParameterException", f"expected InvalidParameterException, got {bad_arn_code!r}"
    expected = "The keyArn for encryptionConfig is invalid."
    assert bad_arn_message == expected, f"expected message {expected!r}, got {bad_arn_message!r}"

    update_id = str(uuid.uuid4())
    update_code, update_message = _error_detail(lambda: c.describe_update(name=name, updateId=update_id))
    assert update_code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {update_code!r}"
    expected = f"No update found for ID: {update_id}"
    assert update_message == expected, f"expected message {expected!r}, got {update_message!r}"
    after = c.describe_cluster(name=name)["cluster"]
    assert not after.get("encryptionConfig"), after.get("encryptionConfig")
    assert after["status"] == "ACTIVE", after["status"]
    after_updates = set(c.list_updates(name=name)["updateIds"])
    assert after_updates == before, f"expected update set unchanged {before}, got {after_updates}"


def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=20.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the shared network.

    DeleteCluster is refused while an update, node group or add-on operation still runs; that
    ResourceInUseException is retried until the deadline.
    """
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            eks.delete_cluster(name=name)
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ResourceInUseException" or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=name)
        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            raise
        time.sleep(interval_s)
    raise AssertionError(f"EKS cluster {name} still exists {timeout_s:.0f}s after DeleteCluster")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
