"""update-pod-identity-association-invalid-namespace-rejected."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "update-pod-identity-association-invalid-namespace-rejected"
GROUP = "negative-classes"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePodIdentityAssociation rejects a policy set without disableSessionTags=true with
    InvalidParameterException and leaves the association untouched; the same update succeeds with
    disableSessionTags=true (the documented update-time rule; namespace itself is immutable)."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)
    pod_role_arn = _create_pod_identity_role(ctx)

    def _create_association():
        return eks.create_pod_identity_association(
            clusterName=cluster_name,
            namespace="default",
            serviceAccount="sim2real-sa",
            roleArn=pod_role_arn,
        )["association"]

    deadline = time.monotonic() + 120
    while True:
        try:
            created = _create_association()
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] in ("InvalidParameterException", "ClientException") and (
                time.monotonic() < deadline
            ):
                time.sleep(2)  # IAM trust-policy propagation delay
                continue
            raise
    assoc_id = created["associationId"]
    ctx.on_cleanup(
        lambda: eks.delete_pod_identity_association(clusterName=cluster_name, associationId=assoc_id)
    )
    assert created["disableSessionTags"] is False

    # positive control: an update on this association -- same operation, valid input -- succeeds,
    # so the later rejection is attributable to the missing disableSessionTags, not to updates
    # being refused wholesale.
    eks.update_pod_identity_association(
        clusterName=cluster_name, associationId=assoc_id, disableSessionTags=True
    )
    baseline = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=assoc_id
    )["association"]
    assert baseline["disableSessionTags"] is True, (
        f"positive control update did not persist disableSessionTags=true: {baseline}"
    )
    eks.update_pod_identity_association(
        clusterName=cluster_name, associationId=assoc_id, disableSessionTags=False
    )
    baseline = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=assoc_id
    )["association"]
    assert baseline["disableSessionTags"] is False, (
        f"positive control reset did not persist disableSessionTags=false: {baseline}"
    )

    least_privilege_policy = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}]}
    )

    code, message = _client_error(
        lambda: eks.update_pod_identity_association(
            clusterName=cluster_name,
            associationId=assoc_id,
            policy=least_privilege_policy,
            disableSessionTags=False,
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "When policy is specified, disableSessionTags must be set to true", message

    # effect absent: the association still has no policy attached
    unchanged = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=assoc_id
    )["association"]
    assert unchanged.get("policy") is None, f"rejected update must not persist a policy: {unchanged}"
    assert unchanged["disableSessionTags"] is False

    # positive control: the same policy succeeds once disableSessionTags=true accompanies it
    eks.update_pod_identity_association(
        clusterName=cluster_name,
        associationId=assoc_id,
        policy=least_privilege_policy,
        disableSessionTags=True,
    )

    # independent read at the destination: the accepted update actually persisted
    settled = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=assoc_id
    )["association"]
    assert settled["policy"] == least_privilege_policy, (
        f"accepted update did not persist a policy: {settled}"
    )
    assert settled["disableSessionTags"] is True, (
        f"accepted update did not persist disableSessionTags=true: {settled}"
    )


# ===== helpers =====
def _client_error(fn):
    """Call fn, require that it raises ClientError, return (Code, Message)."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))[
        "Role"
    ]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _create_vpc_and_subnets(ctx):
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.47.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc")])["Vpc"][
        "VpcId"
    ]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    azs = [z["ZoneName"] for z in ec2.describe_availability_zones()["AvailabilityZones"][:2]]
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.47.{i}.0/24",
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
            eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
            break
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "InvalidParameterException" and time.monotonic() < deadline:
                time.sleep(2)  # IAM role propagation delay
                continue
            raise

    def _cleanup_cluster():
        eks.delete_cluster(name=name)
        waiter = eks.get_waiter("cluster_deleted")
        waiter.wait(name=name, WaiterConfig={"Delay": 2, "MaxAttempts": 900})

    ctx.on_cleanup(_cleanup_cluster)
    waiter = eks.get_waiter("cluster_active")
    waiter.wait(name=name, WaiterConfig={"Delay": 2, "MaxAttempts": 900})
    return name


# EC2 network teardown: a resource in this VPC deletes asynchronously and leaves its ENIs behind for a
# while, so each subnet / security group / VPC delete waits for them and retries DependencyViolation
# to one deadline shared by all of the check's network deletes, then raises naming the ENIs left.
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
        _time.sleep(2)
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
        _time.sleep(2)


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
