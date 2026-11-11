"""fargate-profile-public-subnet-rejected."""
from __future__ import annotations

import ipaddress
import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "fargate-profile-public-subnet-rejected"
GROUP = 'overly-permissive'
SERVICES = ['eks']

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}


_NOT_FOUND = "The requested resource does not exist."
_BAD_TRUST = (
    "Misconfigured PodExecutionRole Trust Policy; Please add the eks-fargate-pods.amazonaws.com "
    "Service Principal"
)


def _error_detail(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _refusal_past_trust_propagation(fn, timeout_s=240.0, interval_s=10.0):
    """Return fn's (Code, Message) refusal once EKS sees a just-created role's trust policy.

    Until IAM propagates a new role, EKS reports the trust-policy refusal even for a correct role,
    so only that refusal is retried (bounded); any other answer returns at once.
    """
    deadline = time.monotonic() + timeout_s
    while True:
        code, message = _error_detail(fn)
        if message != _BAD_TRUST or time.monotonic() >= deadline:
            return code, message
        time.sleep(interval_s)


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
            Tags=[{"Key": "sim2real", "Value": CHECK}],
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


def _delete_role(iam, name, managed_policies):
    for policy_arn in managed_policies:
        try:
            iam.detach_role_policy(RoleName=name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
    iam.delete_role(RoleName=name)


def _retry_transient_role_error(fn, transient_codes, timeout_s=60.0, interval_s=5.0):
    """Retry ``fn`` while IAM's just-created role/policy hasn't yet propagated to EKS.

    Only ``transient_codes`` are retried; every other ClientError, including the rejection under
    test, is raised immediately.
    """
    deadline = time.time() + timeout_s
    last_err = None
    while time.time() < deadline:
        try:
            return fn()
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in transient_codes:
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
    _retry_transient_role_error(
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
        ),
        transient_codes=("AccessDeniedException", "InvalidParameterException"),
    )
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

_FARGATE_POLICY = "arn:aws:iam::aws:policy/AmazonEKSFargatePodExecutionRolePolicy"


_NODE_POLICIES = [
    "arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:aws:iam::aws:policy/AmazonEKS_CNI_Policy",
    "arn:aws:iam::aws:policy/AmazonEC2ContainerRegistryReadOnly",
]


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


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateFargateProfile refuses public subnets and a role without the eks-fargate-pods trust.

    Each refusal is InvalidParameterException with the exact message, and no profile is left behind.
    """
    c = ctx.client("eks")
    iam = ctx.client("iam")
    cluster = _active_cluster(ctx, c, "eks-fpbad-")
    fargate_role_name = ctx.unique_name(PREFIX + "eks-fargate-")
    fargate_role = _ensure_role(ctx, fargate_role_name, "eks-fargate-pods.amazonaws.com", [_FARGATE_POLICY])
    ctx.on_cleanup(lambda: _delete_role(iam, fargate_role_name, [_FARGATE_POLICY]))
    node_role_name = ctx.unique_name(PREFIX + "eks-node-")
    node_role = _ensure_role(ctx, node_role_name, "ec2.amazonaws.com", _NODE_POLICIES)
    ctx.on_cleanup(lambda: _delete_role(iam, node_role_name, _NODE_POLICIES))
    vpc_id = c.describe_cluster(name=cluster)["cluster"]["resourcesVpcConfig"]["vpcId"]
    public = _subnet_ids(ctx)
    profile = ctx.unique_name("fp-bad-")

    # Public subnets are refused for a Fargate profile; EKS names the first subnet it rejects.
    code, message = _refusal_past_trust_propagation(
        lambda: _retry_transient_role_error(
            lambda: c.create_fargate_profile(
                clusterName=cluster,
                fargateProfileName=profile,
                podExecutionRoleArn=fargate_role,
                subnets=public,
                selectors=[{"namespace": "default"}],
            ),
            transient_codes=("AccessDeniedException",),
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    expected = f"Subnet {public[0]} provided in Fargate Profile is not a private subnet"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    code, message = _error_detail(
        lambda: c.describe_fargate_profile(clusterName=cluster, fargateProfileName=profile)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == _NOT_FOUND, f"expected message {_NOT_FOUND!r}, got {message!r}"
    assert profile not in c.list_fargate_profiles(clusterName=cluster)["fargateProfileNames"]

    # A pod execution role without the eks-fargate-pods trust policy is refused. Real private
    # subnets isolate this to the trust rule; public ones would be refused for privateness first.
    private = _private_subnet_ids(ctx, vpc_id)
    code, message = _error_detail(
        lambda: _retry_transient_role_error(
            lambda: c.create_fargate_profile(
                clusterName=cluster,
                fargateProfileName=ctx.unique_name("fp-bad2-"),
                podExecutionRoleArn=node_role,
                subnets=private,
                selectors=[{"namespace": "default"}],
            ),
            transient_codes=("AccessDeniedException",),
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert message == _BAD_TRUST, f"expected message {_BAD_TRUST!r}, got {message!r}"
    code, message = _error_detail(
        lambda: c.delete_fargate_profile(clusterName=cluster, fargateProfileName=profile)
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == _NOT_FOUND, f"expected message {_NOT_FOUND!r}, got {message!r}"


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
