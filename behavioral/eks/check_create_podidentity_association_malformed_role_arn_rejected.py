"""create-podidentity-association-malformed-role-arn-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "create-podidentity-association-malformed-role-arn-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePodIdentityAssociation authorizes iam:PassRole before validating roleArn syntax, so a
    malformed role ARN is rejected with AccessDeniedException and leaves nothing behind, while a
    well-formed pod role succeeds, describes, and deletes cleanly."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)
    namespace = "default"
    service_account = "sim2real-sa"

    code, message = _error(
        lambda: eks.create_pod_identity_association(
            clusterName=cluster_name,
            namespace=namespace,
            serviceAccount=service_account,
            roleArn="not-an-arn-at-all",
        )
    )
    assert code == "AccessDeniedException", f"expected AccessDeniedException, got {code}"
    assert message == "Cross-account pass role is not allowed.", message

    # effect absent: no association was created for this namespace/serviceAccount pair
    listed = eks.list_pod_identity_associations(
        clusterName=cluster_name, namespace=namespace, serviceAccount=service_account
    )["associations"]
    assert listed == [], f"malformed roleArn create should not have persisted an association: {listed}"

    # positive control: a well-formed, assumable role succeeds on the same cluster
    pod_role_arn = _create_pod_identity_role(ctx)
    resp = _create_association_with_retry(
        eks,
        clusterName=cluster_name,
        namespace=namespace,
        serviceAccount=service_account,
        roleArn=pod_role_arn,
    )
    assoc_id = resp["association"]["associationId"]
    ctx.on_cleanup(lambda: _best_effort_delete_assoc(eks, cluster_name, assoc_id))
    assert resp["association"]["roleArn"] == pod_role_arn

    # independent read: the association is visible through a different operation
    # than the one that created it, not just echoed back in the mutating response.
    described = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=assoc_id
    )["association"]
    assert described["associationId"] == assoc_id
    assert described["roleArn"] == pod_role_arn

    # delete proves gone and unusable
    eks.delete_pod_identity_association(clusterName=cluster_name, associationId=assoc_id)
    not_found_code, not_found_message = _error(
        lambda: eks.describe_pod_identity_association(
            clusterName=cluster_name, associationId=assoc_id
        )
    )
    assert not_found_code == "ResourceNotFoundException", not_found_code
    assert not_found_message == f"No service account role association found for ID: {assoc_id}", not_found_message
    remaining = eks.list_pod_identity_associations(clusterName=cluster_name)["associations"]
    assert assoc_id not in {a["associationId"] for a in remaining}


# ===== helpers =====
def _error(fn):
    """Call fn, require it raises ClientError, return (Code, Message)."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")


def _create_association_with_retry(eks, timeout_s=60.0, interval_s=10.0, **kwargs):
    # IAM role trust-policy propagation delay: give the role a bounded window to
    # become assumable rather than sleeping unconditionally before the call.
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return eks.create_pod_identity_association(**kwargs)
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _best_effort_delete_assoc(eks, cluster_name, association_id):
    try:
        eks.delete_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _tag_spec(ctx, resource_type):
    return {
        "ResourceType": resource_type,
        "Tags": [
            {"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-{resource_type}-")},
            {"Key": "sim2real:managed", "Value": "true"},
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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
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


def _create_pod_identity_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-podrole-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pods.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.44.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")])["Vpc"][
        "VpcId"
    ]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.44.{i}.0/24",
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
                tags={"sim2real:managed": "true"},
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
        waiter.wait(name=name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})

    ctx.on_cleanup(_cleanup_cluster)
    waiter = eks.get_waiter("cluster_active")
    waiter.wait(name=name, WaiterConfig={"Delay": 2, "MaxAttempts": 900})
    return name


# EC2 network teardown: a cluster in this VPC deletes asynchronously and its ENIs keep DeleteSubnet /
# DeleteVpc failing with DependencyViolation for minutes, so wait for the ENIs, retry that code to one
# deadline shared by the check's network deletes, then raise naming the ENIs still attached.
_NET_TEARDOWN_S = 840.0
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
