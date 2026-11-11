"""create-capability-unsupported-type-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-capability-unsupported-type-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateCapability with a `type` outside ACK/KRO/ARGOCD is rejected with
    InvalidParameterException and leaves no capability behind, while a supported type (KRO)
    succeeds on the same cluster."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)
    role_arn = _create_capability_role(ctx)

    # Positive control first: prove the role is usable (past any IAM trust-policy
    # propagation delay) before testing the negative, so a rejection below can never be
    # confused with "the role wasn't ready yet" -- both surface as the same
    # InvalidParameterException code.
    good_name = ctx.unique_name("sim2real-cap-kro-")
    created = _create_capability_with_retry(
        eks,
        clusterName=cluster_name,
        capabilityName=good_name,
        type="KRO",
        roleArn=role_arn,
        deletePropagationPolicy="RETAIN",
    )["capability"]
    ctx.on_cleanup(lambda: _delete_capability_and_wait(eks, cluster_name, good_name))
    assert created["type"] == "KRO"
    assert created["capabilityName"] == good_name

    # Now the role is proven usable -- an unsupported `type` value is rejected purely on
    # its own merits, with InvalidParameterException.
    bogus_name = ctx.unique_name("sim2real-cap-bogus-")
    code, message = _error(
        lambda: eks.create_capability(
            clusterName=cluster_name,
            capabilityName=bogus_name,
            type="NOT_A_REAL_CAPABILITY_TYPE",
            roleArn=role_arn,
            deletePropagationPolicy="RETAIN",
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "Invalid capability type", f"unexpected message: {message!r}"

    # effect absent: no capability with that name was created on the cluster, and the
    # earlier, valid capability is still there, unaffected.
    listed = eks.list_capabilities(clusterName=cluster_name)["capabilities"]
    names = [c["capabilityName"] for c in listed]
    assert bogus_name not in names, f"rejected create must not persist a capability: {listed}"
    assert good_name in names, listed


# ===== helpers =====
def _error(fn):
    """Call fn, require it raises ClientError, return the error (Code, Message)."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_capability_and_wait(eks, cluster_name, capability_name, timeout_s=300):
    """Teardown: DeleteCapability is asynchronous and DeleteCluster refuses a cluster that
    still has capabilities attached, so wait (bounded) until the capability is gone."""
    eks.delete_capability(clusterName=cluster_name, capabilityName=capability_name)
    deadline = time.monotonic() + timeout_s
    while True:
        names = [c["capabilityName"] for c in eks.list_capabilities(clusterName=cluster_name)["capabilities"]]
        if capability_name not in names:
            return
        if time.monotonic() >= deadline:
            raise AssertionError(f"capability {capability_name} still attached after {timeout_s}s")
        time.sleep(2)


def _tag_spec(ctx, resource_type):
    return {
        "ResourceType": resource_type,
        "Tags": [
            {"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-{resource_type}-")},
            {"Key": "sim2real-managed", "Value": "true"},
        ],
    }


def _create_cluster_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-clrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))[
        "Role"
    ]["Arn"]
    iam.attach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    )

    def _cleanup():
        iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
        )
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_capability_role(ctx):
    # A capability's role "must have a trust policy that allows the EKS capabilities
    # service principal to assume it" -- empirically capabilities.eks.amazonaws.com,
    # with both sts:AssumeRole and sts:TagSession actions (API_CreateCapability.html +
    # empirical InvalidParameterException message).
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-caprole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "capabilities.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_capability_with_retry(eks, **kwargs) -> dict:
    """CreateCapability can reject a just-created role's trust policy as "invalid" for a
    short window while IAM propagates it; retry on that specific transient signature."""
    deadline = time.monotonic() + 60
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            return eks.create_capability(**kwargs)
        except ClientError as exc:
            last_exc = exc
            if exc.response["Error"]["Code"] == "InvalidParameterException" and "trust policy" in str(exc):
                time.sleep(5)
                continue
            raise
    raise AssertionError(f"create_capability never accepted the role's trust policy: {last_exc}")


def _create_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.48.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")])["Vpc"][
        "VpcId"
    ]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.48.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet")],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)

        def _del_subnet(sid=subnet_id):
            for _ in range(12):
                try:
                    _delete_net(ec2, "delete_subnet", SubnetId=sid)
                    return
                except ClientError as exc:
                    if exc.response["Error"]["Code"] == "DependencyViolation":
                        time.sleep(10)
                        continue
                    raise

        ctx.on_cleanup(_del_subnet)
    return subnet_ids


def _create_active_cluster(ctx):
    eks = ctx.client("eks")
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _create_vpc_and_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-cl-")

    deadline = time.monotonic() + 180
    while True:
        try:
            eks.create_cluster(
                name=name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                # CreateCapability requires access entries, which require the cluster's
                # authenticationMode to be API or API_AND_CONFIG_MAP.
                accessConfig={"authenticationMode": "API"},
            )
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)  # IAM role propagation delay
                continue
            raise

    def _cleanup_cluster():
        eks.delete_cluster(name=name)
        waiter = eks.get_waiter("cluster_deleted")
        waiter.wait(name=name, WaiterConfig={"Delay": 2, "MaxAttempts": 360})

    ctx.on_cleanup(_cleanup_cluster)
    waiter = eks.get_waiter("cluster_active")
    waiter.wait(name=name, WaiterConfig={"Delay": 2, "MaxAttempts": 900})
    return name


# EC2 network teardown: a cluster in this VPC deletes asynchronously and its ENIs keep DeleteSubnet /
# DeleteVpc failing with DependencyViolation for minutes, so wait for the ENIs, retry that code to one
# deadline shared by the check's network deletes, then raise naming the ENIs still attached.
_NET_TEARDOWN_S = 540.0
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
