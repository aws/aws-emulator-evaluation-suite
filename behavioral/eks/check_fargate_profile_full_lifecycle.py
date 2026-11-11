"""fargate-profile-full-lifecycle."""
from __future__ import annotations

import ipaddress
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fargate-profile-full-lifecycle"
GROUP = 'data-plane'
SERVICES = ['eks']

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


def _error(fn):
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
            Tags=[{"Key": "sim2real", "Value": "1"}],
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


def _call_with_role_propagation_retry(fn, timeout_s=90, interval_s=2):
    """Retry ``fn`` while EKS reports a just-created role as not yet usable.

    IAM is eventually consistent: EKS can reject a role that IAM already returns from
    get_role until the trust policy has propagated. A bounded retry on the specific error,
    not a blind sleep before every call regardless of whether the role is fresh.
    """
    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "InvalidParameterException":
                raise
            last_err = exc
            time.sleep(interval_s)
    raise last_err


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


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _wait_for(fn, pred, timeout_s=300, interval_s=2, desc="", ctx=None):
    deadline = time.time() + timeout_s
    while True:
        last = fn()
        if pred(last):
            return last
        if time.time() >= deadline:
            if ctx is not None and _budget_spent(ctx):
                raise TimeoutError(f"{desc}: the run budget ended first; not graded")
            raise AssertionError(f"timed out after {timeout_s}s waiting for {desc}; last={last!r}")
        time.sleep(interval_s)


def _active_cluster(ctx, c, suffix):
    """Provision (create + wait ACTIVE) a throwaway cluster, register cleanup, return its name."""
    role_arn = _ensure_role(ctx, CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY])
    name = ctx.unique_name(PREFIX + suffix)
    _call_with_role_propagation_retry(
        lambda: c.create_cluster(
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
        )
    )
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(c, name))
    resp = _wait_for(
        lambda: c.describe_cluster(name=name),
        lambda r: r["cluster"]["status"] in ("ACTIVE", "FAILED"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, 1500),
        interval_s=2,
        desc=f"cluster {name} status==ACTIVE",
    )
    cluster = resp["cluster"]
    assert cluster["status"] == "ACTIVE", f"cluster {name} landed in {cluster['status']!r}"
    return name

_FARGATE_POLICY = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"


def _private_subnet_ids(ctx, vpc_id, count=2):
    """Create ``count`` private subnets (own route table, VPC-local route only) and return their ids.

    To EKS a subnet is private when its route table has no default route to an internet gateway.
    No NAT gateway: egress is only needed by Pods, and none is scheduled here.
    """
    ec2 = ctx.client("ec2")
    vpc = ec2.describe_vpcs(VpcIds=[vpc_id])["Vpcs"][0]
    existing = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]).get("Subnets", [])
    azs = sorted({s["AvailabilityZone"] for s in existing if s["AvailabilityZoneId"] not in _BAD_AZS})[:count]
    if len(azs) < count:
        raise AssertionError(f"need >={count} EKS-supported AZs in {vpc_id}, found {len(azs)}")
    taken = [ipaddress.ip_network(s["CidrBlock"]) for s in existing]
    free = [
        net
        for net in ipaddress.ip_network(vpc["CidrBlock"]).subnets(new_prefix=24)
        if not any(net.overlaps(t) for t in taken)
    ]
    if len(free) < count:
        raise AssertionError(f"no free /24 in {vpc_id} ({vpc['CidrBlock']}) to carve a private subnet from")
    rtb = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "route-table", "Tags": [{"Key": "Name", "Value": PREFIX + "eks-private-rtb"}]}
        ],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: ec2.delete_route_table(RouteTableId=rtb))
    private = []
    for az, cidr in zip(azs, free[-count:]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=str(cidr),
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": PREFIX + "eks-private-subnet"}]}
            ],
        )["Subnet"]["SubnetId"]
        # Registered before the association so cleanup runs subnet-delete first (LIFO) — deleting
        # a subnet drops its route-table association, which is what lets the route table go next.
        ctx.on_cleanup(lambda s=subnet_id: ec2.delete_subnet(SubnetId=s))
        ec2.associate_route_table(RouteTableId=rtb, SubnetId=subnet_id)
        private.append(subnet_id)
    return private


def _profile_gone(c, cluster, profile):
    """Whether DescribeFargateProfile reports the profile not found; any other error raises."""
    try:
        c.describe_fargate_profile(clusterName=cluster, fargateProfileName=profile)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFoundException":
            return True
        raise
    return False


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A Fargate profile goes CREATING -> ACTIVE -> DELETING -> gone, consistently listed/described.

    ACTIVE echoes the selectors, subnets and role; a duplicate name is ResourceInUseException.
    """
    c = ctx.client("eks")
    cluster = _active_cluster(ctx, c, "eks-fp-")
    fargate_role_name = ctx.unique_name(PREFIX + "eks-fargate-")
    fargate_role = _ensure_role(ctx, fargate_role_name, "eks-fargate-pods.amazonaws.com", [_FARGATE_POLICY])
    iam = ctx.client("iam")

    def _cleanup_fargate_role():
        try:
            iam.detach_role_policy(RoleName=fargate_role_name, PolicyArn=_FARGATE_POLICY)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=fargate_role_name)

    ctx.on_cleanup(_cleanup_fargate_role)
    vpc_id = c.describe_cluster(name=cluster)["cluster"]["resourcesVpcConfig"]["vpcId"]
    private = _private_subnet_ids(ctx, vpc_id)
    profile = ctx.unique_name("fp-")
    selectors = [{"namespace": "sim2real-ns", "labels": {"tier": "web"}}]

    created = _call_with_role_propagation_retry(
        lambda: c.create_fargate_profile(
            clusterName=cluster,
            fargateProfileName=profile,
            podExecutionRoleArn=fargate_role,
            subnets=private,
            selectors=selectors,
            tags={"sim2real": "1"},
        )
    )["fargateProfile"]
    ctx.on_cleanup(lambda: _gone_ok(lambda: c.delete_fargate_profile(clusterName=cluster, fargateProfileName=profile)))
    assert created["status"] == "CREATING", created
    assert created["fargateProfileName"] == profile, created
    assert profile in c.list_fargate_profiles(clusterName=cluster)["fargateProfileNames"]

    active = _wait_for(
        lambda: c.describe_fargate_profile(clusterName=cluster, fargateProfileName=profile)["fargateProfile"],
        lambda f: f["status"] in ("ACTIVE", "CREATE_FAILED"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, 420), interval_s=2, desc=f"fargate profile {profile} ACTIVE",
    )
    assert active["status"] == "ACTIVE", f"fargate profile landed in {active['status']!r}"
    assert active["selectors"] == selectors, active["selectors"]
    assert set(active["subnets"]) == set(private), active["subnets"]
    assert active["podExecutionRoleArn"] == fargate_role, active
    assert active["fargateProfileArn"], active
    assert active["clusterName"] == cluster, active

    dup_code, dup_msg = _error(
        lambda: c.create_fargate_profile(
            clusterName=cluster,
            fargateProfileName=profile,
            podExecutionRoleArn=fargate_role,
            subnets=private,
            selectors=[{"namespace": "sim2real-ns"}],
        )
    )
    assert dup_code == "ResourceInUseException", dup_code
    assert dup_msg == "A Fargate Profile already exists with this name in this cluster.", dup_msg

    deleting = c.delete_fargate_profile(clusterName=cluster, fargateProfileName=profile)["fargateProfile"]
    assert deleting["status"] == "DELETING", deleting

    _wait_for(
        lambda: _profile_gone(c, cluster, profile),
        lambda gone: gone,
        ctx=ctx,
        timeout_s=_budget_s(ctx, 420), interval_s=2, desc=f"fargate profile {profile} gone",
    )
    gone_code, gone_msg = _error(lambda: c.describe_fargate_profile(clusterName=cluster, fargateProfileName=profile))
    assert gone_code == "ResourceNotFoundException", gone_code
    assert gone_msg == "The requested resource does not exist.", gone_msg
    assert profile not in c.list_fargate_profiles(clusterName=cluster)["fargateProfileNames"]


def _gone_ok(fn):
    """Run a teardown call; a resource the check already deleted in band is done, not a leak."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise



def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=2.0):
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
