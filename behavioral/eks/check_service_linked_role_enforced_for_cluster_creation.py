"""service-linked-role-enforced-for-cluster-creation."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "service-linked-role-enforced-for-cluster-creation"
GROUP = "server-side"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCluster accepts an eks.amazonaws.com-trusted role with zero attached policies.

    The role is echoed back, the cluster reaches ACTIVE, and the role still carries no policies.
    """
    eks = ctx.client("eks")
    iam = ctx.client("iam")
    subnet_ids = _get_or_create_subnets(ctx)

    bad_role_name, bad_role_arn = _create_role_trust_only(ctx)
    attached = iam.list_attached_role_policies(RoleName=bad_role_name)["AttachedPolicies"]
    assert attached == [], f"expected zero attached policies on {bad_role_name}, got {attached!r}"
    got_role = iam.get_role(RoleName=bad_role_name)["Role"]
    assert got_role["RoleName"] == bad_role_name, (
        f"expected get_role to return {bad_role_name!r}, got {got_role['RoleName']!r}"
    )

    bad_cluster_name = ctx.unique_name("sim2real-eks-noperm-")
    # Only the IAM-propagation "not authorized" ClientException is retried; any other refusal
    # of the policy-less role raises here.
    created = _create_cluster_with_retry(ctx, bad_cluster_name, bad_role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _delete_cluster(ctx, bad_cluster_name))
    assert created["cluster"]["roleArn"] == bad_role_arn, (
        f"CreateCluster echoed roleArn {created['cluster']['roleArn']!r}, expected the policy-less "
        f"role {bad_role_arn!r} -- the cluster under test must actually be the one using it"
    )

    # The missing managed policy does not park the cluster in FAILED either.
    cluster = _wait_cluster_status(ctx, bad_cluster_name, {"ACTIVE", "FAILED"}, timeout_s=1200.0)
    assert cluster["status"] == "ACTIVE", (
        f"cluster created with a role carrying ZERO attached policies reached "
        f"{cluster['status']!r}; real AWS takes it to ACTIVE (measured 527s and "
        f"482s for an even weaker, unassumable role), so a FAILED or rejected "
        f"outcome is a divergence, not enforcement"
    )
    described = eks.describe_cluster(name=bad_cluster_name)["cluster"]
    assert described["roleArn"] == bad_role_arn, (
        f"DescribeCluster reports roleArn {described['roleArn']!r}, expected {bad_role_arn!r}"
    )
    still_empty = iam.list_attached_role_policies(RoleName=bad_role_name)["AttachedPolicies"]
    assert still_empty == [], (
        f"the cluster role acquired attached policies during provisioning ({still_empty!r}); the "
        f"ACTIVE cluster above must be attributable to a role that never carried any"
    )


from botocore.exceptions import ClientError  # noqa: E402


def _get_or_create_subnets(ctx):
    ec2 = ctx.client("ec2")
    default_vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if default_vpcs:
        vpc_id = default_vpcs[0]["VpcId"]
        subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
        by_az = {}
        for s in subnets:
            by_az.setdefault(s["AvailabilityZone"], s["SubnetId"])
        subnet_ids = list(by_az.values())[:3]
        if len(subnet_ids) >= 2:
            return subnet_ids
    # No usable shared network: provision a dedicated one.
    vpc_id = ec2.create_vpc(CidrBlock="10.44.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "sim2real", "Value": "1"}])
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ][:2]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock=f"10.44.{i}.0/24", AvailabilityZone=az)["Subnet"][
            "SubnetId"
        ]
        ec2.create_tags(Resources=[subnet_id], Tags=[{"Key": "sim2real", "Value": "1"}])
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_role_trust_only(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-nopolicy-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=[{"Key": "sim2real", "Value": "1"}]
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_name, resp["Role"]["Arn"]


#: Upper bound for a fresh IAM role to become usable by EKS CreateCluster.
_IAM_PROPAGATION_S = 120.0


def _create_cluster_with_retry(ctx, name, role_arn, subnet_ids, **kwargs):
    """CreateCluster, retrying only the IAM-propagation "not authorized" ClientException."""
    eks = ctx.client("eks")
    budget = _IAM_PROPAGATION_S
    left = ctx.time_left()
    if left is not None:
        budget = min(budget, left)
    deadline = time.monotonic() + budget
    while True:
        try:
            return eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags={"sim2real": "1"},
                **kwargs,
            )
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "").lower()
            if code == "ClientException" and "not authorized" in message and time.monotonic() < deadline:
                time.sleep(2)
                continue
            raise


def _wait_cluster_status(ctx, name, statuses, timeout_s=1200.0, interval_s=20.0):
    eks = ctx.client("eks")
    deadline = time.monotonic() + timeout_s
    cluster = None
    while True:
        cluster = eks.describe_cluster(name=name)["cluster"]
        if cluster["status"] in statuses:
            return cluster
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"cluster {name} did not reach {statuses} within {timeout_s}s "
                f"(last={cluster['status']})"
            )
        time.sleep(interval_s)


def _delete_cluster(ctx, name):
    _delete_eks_cluster_and_wait(ctx.client("eks"), name)


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
