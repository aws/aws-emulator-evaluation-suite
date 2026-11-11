"""capability-update-requires-existing-ordering."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

PREFIX = "sim2real-behav-"
CLUSTER_ROLE = PREFIX + "eks-cluster-role"
_EKS_CLUSTER_POLICY = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
_BAD_AZS = {"use1-az3", "usw1-az2", "usw2-az4", "cac1-az3", "cac1-az4"}
_CAPABILITY_PRINCIPAL = "capabilities.eks.amazonaws.com"


def _trust(service: str, extra_actions: tuple[str, ...] = ()) -> str:
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

def _ensure_role(ctx, name, service="eks.amazonaws.com", managed_policies=(), extra_actions=()):
    """Create-or-reuse an IAM role and return its ARN."""
    iam = ctx.client("iam")
    try:
        arn = iam.create_role(
            RoleName=name,
            AssumeRolePolicyDocument=_trust(service, extra_actions),
            Description="SimParityProbe EKS behavioral fidelity fixture",
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

_GONE_CODES = ("NoSuchEntity", "ResourceNotFoundException", "InvalidInternetGatewayID.NotFound", "Gateway.NotAttached")


def _swallow(fn):
    """Teardown call: a resource (or attachment) already gone is fine; every other error raises."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in _GONE_CODES:
            raise

def _ephemeral_capability_role(ctx, label):
    """A single-use IAM role trusted by the capabilities controller, cleaned up on exit."""
    iam = ctx.client("iam")
    name = ctx.unique_name(PREFIX + label)
    arn = iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=_trust(_CAPABILITY_PRINCIPAL, ("sts:TagSession",)),
        Description="SimParityProbe EKS behavioral fidelity fixture",
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _swallow(lambda: iam.delete_role(RoleName=name)))
    return arn

def _subnet_ids(ctx):
    """Two subnets in two distinct, EKS-supported AZs — the shared network's if usable, else a
    dedicated VPC this check provisions itself (a freshly provisioned account may have no
    shared network at all)."""
    ec2 = ctx.client("ec2")
    resp = ec2.describe_subnets(Filters=[{"Name": "subnet-id", "Values": ctx.network().subnet_ids}])
    subnets = resp.get("Subnets", [])
    by_az: dict[str, str] = {}
    for sn in sorted(subnets, key=lambda s: s["AvailabilityZone"]):
        az = sn["AvailabilityZone"]
        if sn["AvailabilityZoneId"] in _BAD_AZS:
            continue
        by_az.setdefault(az, sn["SubnetId"])
    if len(by_az) >= 2:
        return [by_az[az] for az in sorted(by_az)][:2]
    return _create_dedicated_subnets(ctx)

_NET_GONE_CODES = (
    "InvalidVpcID.NotFound",
    "InvalidSubnetID.NotFound",
    "InvalidRouteTableID.NotFound",
    "InvalidAssociationID.NotFound",
    "InvalidInternetGatewayID.NotFound",
    "Gateway.NotAttached",
)


def _retry_delete(fn, release_s=540.0):
    """Teardown call: retries DependencyViolation while the deleted cluster's ENIs drain; gone is fine."""
    deadline = time.monotonic() + release_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code", "")
            if code in _NET_GONE_CODES:
                return
            if code != "DependencyViolation" or time.monotonic() >= deadline:
                raise
            time.sleep(2)

def _create_dedicated_subnets(ctx):
    """Provision a minimal VPC + IGW + route table + two subnets in distinct AZs."""
    ec2 = ctx.client("ec2")
    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    az_names = [a["ZoneName"] for a in azs if a["ZoneId"] not in _BAD_AZS][:2]
    if len(az_names) < 2:
        raise AssertionError(f"need >=2 EKS-supported AZs available, found {az_names}")

    vpc_id = ec2.create_vpc(
        CidrBlock="10.79.0.0/16",
        TagSpecifications=[
            {"ResourceType": "vpc", "Tags": [{"Key": "Name", "Value": ctx.unique_name(PREFIX + "eks-vpc-")}]}
        ],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    igw_id = ec2.create_internet_gateway(
        TagSpecifications=[
            {"ResourceType": "internet-gateway", "Tags": [{"Key": "Name", "Value": ctx.unique_name(PREFIX + "eks-igw-")}]}
        ]
    )["InternetGateway"]["InternetGatewayId"]
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)

    def _teardown_igw():
        _retry_delete(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
        _retry_delete(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id))

    ctx.on_cleanup(_teardown_igw)

    rt_id = ec2.create_route_table(
        VpcId=vpc_id,
        TagSpecifications=[
            {"ResourceType": "route-table", "Tags": [{"Key": "Name", "Value": ctx.unique_name(PREFIX + "eks-rt-")}]}
        ],
    )["RouteTable"]["RouteTableId"]
    ctx.on_cleanup(lambda: _retry_delete(lambda: ec2.delete_route_table(RouteTableId=rt_id)))
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)

    subnet_ids = []
    for i, az in enumerate(az_names):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.79.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[
                {"ResourceType": "subnet", "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"{PREFIX}eks-subnet{i}-")}]}
            ],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _retry_delete(lambda: ec2.delete_subnet(SubnetId=sid)))
        assoc_id = ec2.associate_route_table(RouteTableId=rt_id, SubnetId=subnet_id)["AssociationId"]
        ctx.on_cleanup(lambda aid=assoc_id: _retry_delete(lambda: ec2.disassociate_route_table(AssociationId=aid)))
        subnet_ids.append(subnet_id)
    return subnet_ids

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

def _error(fn):
    """Call fn, require it raises ClientError, return its (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError("expected the call to fail, but it succeeded")

def _cluster_status(c, name):
    try:
        return c.describe_cluster(name=name)["cluster"]["status"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return "GONE"
        raise

def _cluster_params(ctx, name, version=None):
    params = dict(
        name=name,
        roleArn=_ensure_role(ctx, CLUSTER_ROLE, "eks.amazonaws.com", [_EKS_CLUSTER_POLICY]),
        resourcesVpcConfig={
            "subnetIds": _subnet_ids(ctx),
            "endpointPublicAccess": True,
            "endpointPrivateAccess": False,
        },
        accessConfig={"authenticationMode": "API_AND_CONFIG_MAP"},
    )
    if version:
        params["version"] = version
    return params

def _create_cluster_with_retry(c, params, attempts=40, delay_s=2):
    """CreateCluster validates the cluster role's trust policy, which a role this check just
    created may not have propagated to yet (IAM is eventually consistent). Retry the call itself
    on that specific rejection rather than sleeping first."""
    last_err = None
    for _ in range(attempts):
        try:
            c.create_cluster(**params)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code in ("ClientException", "InvalidParameterException"):
                last_err = exc
                time.sleep(delay_s)
                continue
            raise
    raise last_err

def _provision_cluster(ctx, version=None):
    """Create a cluster owned solely by this check and wait for ACTIVE."""
    c = ctx.client("eks")
    name = ctx.unique_name("sim2real-behav-eks-cl-")
    _create_cluster_with_retry(c, _cluster_params(ctx, name, version=version))
    ctx.on_cleanup(lambda: _delete_eks_cluster_and_wait(c, name))
    _wait_for(
        lambda: _cluster_status(c, name),
        lambda s: s in ("ACTIVE", "FAILED"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, 1500),
        interval_s=2,
        desc=f"cluster {name} status==ACTIVE",
    )
    status = _cluster_status(c, name)
    assert status == "ACTIVE", f"cluster {name} reached {status}, expected ACTIVE"
    return name

def _capability_names(listed):
    return [x if isinstance(x, str) else x.get("name", x.get("capabilityName")) for x in listed]

def _describe_capability_or(c, cluster, name, fallback_status):
    """DescribeCapability, mapping the transient 404 that can follow a create/update/delete to
    {"status": fallback_status} so the caller treats it as still in flight; other errors raise."""
    try:
        return c.describe_capability(clusterName=cluster, capabilityName=name)["capability"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
            return {"status": fallback_status}
        raise

def _retry_on_trust_policy_lag(fn, timeout_s=180, interval_s=2):
    """Call fn(), retrying while EKS rejects a just-created role that IAM has not yet propagated
    (IAM is eventually consistent): a trust policy it cannot read yet, or an access entry it
    cannot create yet ("Retry if the role was created recently"). CreateCapability and
    UpdateCapability both do this."""
    deadline = time.time() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"].get("Message", "").lower()
            lag = "trust policy" in msg or "retry if the role was created recently" in msg
            if code == "InvalidParameterException" and lag and time.time() < deadline:
                time.sleep(interval_s)
                continue
            raise

def _create_capability_with_retry(c, cluster, name, role_arn, timeout_s=180, interval_s=2):
    return _retry_on_trust_policy_lag(
        lambda: c.create_capability(
            clusterName=cluster,
            capabilityName=name,
            type="KRO",
            roleArn=role_arn,
            deletePropagationPolicy="RETAIN",
        ),
        timeout_s=timeout_s,
        interval_s=interval_s,
    )

CHECK = "capability-update-requires-existing-ordering"
GROUP = 'overly-permissive'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """UpdateCapability, DeleteCapability and DescribeCapability on a never-created capability
    fail with ResourceNotFoundException, succeed once it exists, and fail the same way after it
    is deleted."""
    c = ctx.client("eks")
    if not (hasattr(c, "update_capability") and hasattr(c, "delete_capability")):
        raise AssertionError("EKS Capability API not present in this botocore version")
    cluster = _provision_cluster(ctx)
    cap = ctx.unique_name("sim2real-behav-cap-")[:63]

    listed = c.list_capabilities(clusterName=cluster).get("capabilities", [])
    assert cap not in _capability_names(listed), f"fresh capability name unexpectedly present: {listed}"

    # (1) before the capability ever exists, every single-resource verb 404s.
    upd = _error(lambda: c.update_capability(clusterName=cluster, capabilityName=cap))
    assert upd == ("ResourceNotFoundException", "The requested resource does not exist."), (
        f"UpdateCapability on a non-existent capability must be "
        f"ResourceNotFoundException, got {upd}"
    )
    dele = _error(lambda: c.delete_capability(clusterName=cluster, capabilityName=cap))
    assert dele == ("ResourceNotFoundException", "The requested resource does not exist."), (
        f"DeleteCapability on a non-existent capability must be "
        f"ResourceNotFoundException, got {dele}"
    )
    desc = _error(lambda: c.describe_capability(clusterName=cluster, capabilityName=cap))
    assert desc == ("ResourceNotFoundException", "The requested resource does not exist."), (
        f"DescribeCapability on a non-existent capability must be "
        f"ResourceNotFoundException, got {desc}"
    )

    # (2) positive control: once a real capability with that exact name exists, the SAME
    # operations succeed. Without this leg, a target that always answers
    # ResourceNotFoundException to every UpdateCapability/DeleteCapability/DescribeCapability —
    # regardless of whether the capability exists — would pass everything asserted above.
    role_arn = _ephemeral_capability_role(ctx, "eks-cap-role-")
    created = _create_capability_with_retry(c, cluster, cap, role_arn)["capability"]
    ctx.on_cleanup(lambda: _swallow(lambda: c.delete_capability(clusterName=cluster, capabilityName=cap)))
    assert created["capabilityName"] == cap, created
    assert created["status"] in ("CREATING", "ACTIVE"), created

    listed_after_create = c.list_capabilities(clusterName=cluster).get("capabilities", [])
    assert cap in _capability_names(listed_after_create), (
        f"just-created capability not visible in ListCapabilities: {listed_after_create}"
    )

    active = _wait_for(
        lambda: _describe_capability_or(c, cluster, cap, "CREATING"),
        lambda cp: cp["status"] in ("ACTIVE", "CREATE_FAILED"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, 900),
        interval_s=2,
        desc=f"capability {cap} status==ACTIVE",
    )
    assert active["status"] == "ACTIVE", f"capability {cap} reached {active['status']}, expected ACTIVE"

    role_arn_2 = _ephemeral_capability_role(ctx, "eks-cap-role2-")
    update_resp = _retry_on_trust_policy_lag(
        lambda: c.update_capability(clusterName=cluster, capabilityName=cap, roleArn=role_arn_2)
    )["update"]
    assert update_resp["id"], f"UpdateCapability on an existing capability should succeed, got {update_resp}"

    settled = _wait_for(
        lambda: _describe_capability_or(c, cluster, cap, "UPDATING"),
        lambda cp: cp["status"] in ("ACTIVE", "UPDATE_FAILED"),
        ctx=ctx,
        timeout_s=_budget_s(ctx, 900),
        interval_s=2,
        desc=f"capability {cap} settle after UpdateCapability",
    )
    assert settled["status"] == "ACTIVE", f"capability {cap} update settled to {settled['status']}"
    assert settled.get("roleArn") == role_arn_2, (
        f"capability {cap} roleArn after update: expected {role_arn_2}, got {settled.get('roleArn')}"
    )

    desc_existing = c.describe_capability(clusterName=cluster, capabilityName=cap)["capability"]
    assert desc_existing["capabilityName"] == cap, desc_existing

    # (3) delete the real capability, then prove the SAME not-found code returns once it is
    # actually gone -- the mirror image of beat (1), now earned rather than assumed.
    c.delete_capability(clusterName=cluster, capabilityName=cap)
    _wait_for(
        lambda: _describe_capability_or(c, cluster, cap, "GONE"),
        lambda cp: cp["status"] == "GONE",
        ctx=ctx,
        timeout_s=_budget_s(ctx, 600),
        interval_s=2,
        desc=f"capability {cap} deleted",
    )
    final_desc = _error(lambda: c.describe_capability(clusterName=cluster, capabilityName=cap))
    assert final_desc == ("ResourceNotFoundException", "The requested resource does not exist."), (
        f"deleted capability must 404 on DescribeCapability, got {final_desc}"
    )
    final_listed = c.list_capabilities(clusterName=cluster).get("capabilities", [])
    assert cap not in _capability_names(final_listed), (
        f"deleted capability still present in ListCapabilities: {final_listed}"
    )


def _delete_eks_cluster_and_wait(eks, name, timeout_s=1200.0, interval_s=3.0):
    """Delete an EKS cluster and wait until it is gone, so its ENIs leave the shared network;
    ResourceInUseException (an update, node group or add-on still running) is retried."""
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
