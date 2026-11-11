"""update-pod-identity-association-malformed-target-rejected."""
from __future__ import annotations

import json
import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-pod-identity-association-malformed-target-rejected"
GROUP = "overly-permissive"
SERVICES = ["eks"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdatePodIdentityAssociation with a malformed targetRoleArn is rejected with
    InvalidParameterException (not ResourceNotFoundException) and does not mutate the association."""
    eks = ctx.client("eks")
    cluster_name = _create_active_cluster(ctx)
    role_arn = _create_pod_identity_role(ctx)

    service_account = ctx.unique_name("sim2real-sa-")[:63]
    created = _retry_while_trust_propagates(
        lambda: eks.create_pod_identity_association(
            clusterName=cluster_name,
            namespace="default",
            serviceAccount=service_account,
            roleArn=role_arn,
        )
    )
    association_id = created["association"]["associationId"]
    assert created["association"].get("targetRoleArn") is None, (
        f"expected no targetRoleArn on creation, got {created['association'].get('targetRoleArn')!r}"
    )

    # break exactly one thing: update with a syntactically malformed targetRoleArn
    code, message = _client_error(
        lambda: eks.update_pod_identity_association(
            clusterName=cluster_name,
            associationId=association_id,
            targetRoleArn="not-a-valid-iam-role-arn",
        )
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code!r}"
    assert message == "The provided targetRoleArn not-a-valid-iam-role-arn is invalid.", message

    # effect absent: the association's targetRoleArn must still be unset
    still = eks.describe_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    assert still["association"].get("targetRoleArn") is None, (
        f"targetRoleArn should remain unset after rejected update, got {still['association'].get('targetRoleArn')!r}"
    )

    # positive control: a well-formed update (toggling disableSessionTags) succeeds
    updated = eks.update_pod_identity_association(
        clusterName=cluster_name, associationId=association_id, disableSessionTags=True
    )
    assert updated["association"]["disableSessionTags"] is True, (
        f"expected disableSessionTags True in update response, got {updated['association']['disableSessionTags']!r}"
    )
    confirm = eks.describe_pod_identity_association(clusterName=cluster_name, associationId=association_id)
    assert confirm["association"]["disableSessionTags"] is True, (
        f"expected disableSessionTags True on independent read, got {confirm['association']['disableSessionTags']!r}"
    )


# ===== helpers =====
_EKS_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
)

_POD_IDENTITY_TRUST_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "pods.eks.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
)


def _create_pod_identity_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-podid-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_POD_IDENTITY_TRUST_POLICY)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _retry_while_trust_propagates(fn: Any, timeout_s: float = 120.0, interval_s: float = 10.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception = RuntimeError("no attempt made")
    while time.monotonic() < deadline:
        try:
            return fn()
        except Exception as exc:  # IAM role trust-policy propagation delay
            last_exc = exc
            time.sleep(interval_s)
    raise last_exc


def _tag_spec(ctx: Any, resource_type: str, name_prefix: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": ctx.unique_name(f"sim2real-eks-{name_prefix}-")}],
    }


def _create_cluster_role(ctx: Any) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-eks-role-")
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=_EKS_TRUST_POLICY)["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonEKSClusterPolicy")
    )
    return role_arn


def _create_cluster_subnets(ctx: Any) -> list:
    ec2 = ctx.client("ec2")
    azs = [
        z["ZoneName"]
        for z in ec2.describe_availability_zones(
            Filters=[
                {"Name": "zone-type", "Values": ["availability-zone"]},
                {"Name": "state", "Values": ["available"]},
            ]
        )["AvailabilityZones"]
    ][:2]
    vpc_id = ec2.create_vpc(CidrBlock="10.42.0.0/16", TagSpecifications=[_tag_spec(ctx, "vpc", "vpc")])["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    subnet_ids = []
    for i, az in enumerate(azs):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.42.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec(ctx, "subnet", "subnet")],
        )["Subnet"]["SubnetId"]
        ctx.on_cleanup(lambda sid=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=sid))
        subnet_ids.append(subnet_id)
    return subnet_ids


def _create_active_cluster(ctx: Any) -> str:
    """Creates a minimal EKS cluster (control plane only) and blocks until ACTIVE."""
    eks = ctx.client("eks")
    role_arn = _create_cluster_role(ctx)
    subnet_ids = _create_cluster_subnets(ctx)
    name = ctx.unique_name("sim2real-eks-cluster-")
    _retry_while_trust_propagates(
        lambda: eks.create_cluster(name=name, roleArn=role_arn, resourcesVpcConfig={"subnetIds": subnet_ids})
    )

    def _cleanup_cluster() -> None:
        try:
            eks.delete_cluster(name=name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise
            return
        deadline = time.monotonic() + 900.0
        while time.monotonic() < deadline:
            try:
                eks.describe_cluster(name=name)
            except eks.exceptions.ResourceNotFoundException:
                return
            time.sleep(15.0)

    ctx.on_cleanup(_cleanup_cluster)

    deadline = time.monotonic() + 1200.0
    status = None
    while time.monotonic() < deadline:
        status = eks.describe_cluster(name=name)["cluster"]["status"]
        if status == "ACTIVE":
            return name
        if status == "FAILED":
            raise AssertionError(f"cluster {name} entered FAILED while waiting for ACTIVE")
        time.sleep(2)
    raise AssertionError(f"cluster {name} did not reach ACTIVE within timeout (last status={status})")


def _client_error(fn):
    """Call fn, require that it raises ClientError, return (Code, Message)."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err["Message"]
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


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
