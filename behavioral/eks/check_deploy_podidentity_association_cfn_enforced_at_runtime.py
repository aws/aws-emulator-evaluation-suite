"""deploy-podidentity-association-cfn-enforced-at-runtime."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-podidentity-association-cfn-enforced-at-runtime"
GROUP = "deploy"
SERVICES = ["eks"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A CFN-deployed AWS::EKS::PodIdentityAssociation is listed and described by EKS
    with exactly the template's namespace / service-account / role binding, the
    binding the Pod Identity Agent consults when it hands credentials to a pod."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")
    cfn = ctx.client("cloudformation")

    subnet_ids = _create_vpc_and_subnets(ctx, ec2)
    cluster_role_arn = _create_cluster_role(ctx, iam)
    target_role_arn = _create_pod_identity_target_role(ctx, iam)

    cluster_name = ctx.unique_name("sim2real-eks-cl-")
    _create_cluster_with_retry(eks, cluster_name, cluster_role_arn, subnet_ids)
    ctx.on_cleanup(lambda: _delete_cluster(eks, cluster_name))
    _poll_until(
        lambda: eks.describe_cluster(name=cluster_name)["cluster"],
        lambda c: c["status"] in ("ACTIVE", "FAILED"),
        timeout_s=1200,
        interval_s=20,
    )
    final_status = eks.describe_cluster(name=cluster_name)["cluster"]["status"]
    assert final_status == "ACTIVE", f"expected cluster {cluster_name} ACTIVE, got {final_status}"

    stack_name = ctx.unique_name("sim2real-eks-pidstack-")
    namespace = "sim2real-ns"
    service_account = "sim2real-sa"

    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Parameters": {
                "ClusterNameParam": {"Type": "String"},
                "NamespaceParam": {"Type": "String"},
                "ServiceAccountParam": {"Type": "String"},
                "RoleArnParam": {"Type": "String"},
            },
            "Resources": {
                "PodIdAssoc": {
                    "Type": "AWS::EKS::PodIdentityAssociation",
                    "Properties": {
                        "ClusterName": {"Ref": "ClusterNameParam"},
                        "Namespace": {"Ref": "NamespaceParam"},
                        "ServiceAccount": {"Ref": "ServiceAccountParam"},
                        "RoleArn": {"Ref": "RoleArnParam"},
                    },
                }
            },
            "Outputs": {
                "AssociationId": {"Value": {"Fn::GetAtt": ["PodIdAssoc", "AssociationId"]}}
            },
        }
    )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=template,
        Parameters=[
            {"ParameterKey": "ClusterNameParam", "ParameterValue": cluster_name},
            {"ParameterKey": "NamespaceParam", "ParameterValue": namespace},
            {"ParameterKey": "ServiceAccountParam", "ParameterValue": service_account},
            {"ParameterKey": "RoleArnParam", "ParameterValue": target_role_arn},
        ],
    )
    ctx.on_cleanup(lambda: _delete_stack(cfn, stack_name))
    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450}
    )

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    association_id = outputs["AssociationId"]

    described = eks.describe_pod_identity_association(
        clusterName=cluster_name, associationId=association_id
    )["association"]
    assert described["namespace"] == namespace, (
        f"expected namespace {namespace!r}, got {described['namespace']!r}"
    )
    assert described["serviceAccount"] == service_account, (
        f"expected serviceAccount {service_account!r}, got {described['serviceAccount']!r}"
    )
    assert described["roleArn"] == target_role_arn, (
        f"expected roleArn {target_role_arn!r}, got {described['roleArn']!r}"
    )

    listed = eks.list_pod_identity_associations(
        clusterName=cluster_name, namespace=namespace, serviceAccount=service_account
    )["associations"]
    matches = [a for a in listed if a["associationId"] == association_id]
    assert len(matches) == 1, (
        f"expected exactly 1 association {association_id!r} under {namespace}/{service_account}, "
        f"found {len(matches)} in {listed!r}"
    )
    assert matches[0]["namespace"] == namespace, (
        f"expected listed namespace {namespace!r}, got {matches[0]['namespace']!r}"
    )
    assert matches[0]["serviceAccount"] == service_account, (
        f"expected listed serviceAccount {service_account!r}, got {matches[0]['serviceAccount']!r}"
    )


# ===== helpers =====


def _poll_until(probe, predicate, timeout_s: float, interval_s: float = 15.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_cluster_with_retry(eks, cluster_name: str, role_arn: str, subnet_ids: list[str]) -> None:
    """A freshly attached cluster-role policy can lag IAM's read path for a few
    seconds; retry the specific InvalidParameterException CreateCluster raises
    for that lag within a bounded window instead of guessing a fixed delay."""
    deadline = time.monotonic() + 90.0
    last_error: Exception | None = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(
                name=cluster_name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
            )
            return
        except eks.exceptions.ClientException as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code != "InvalidParameterException":
                raise
            last_error = exc
            time.sleep(5.0)
    raise AssertionError(f"CreateCluster never succeeded (IAM propagation?): {last_error}")


# Not-found codes of the teardown calls below: the resource is already gone.
_GONE_CODES = {"NoSuchEntity", "InvalidVpcID.NotFound", "InvalidSubnetID.NotFound"}


def _safe(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") not in _GONE_CODES:
            raise


def _tag_spec(resource_type: str, name: str) -> dict:
    return {
        "ResourceType": resource_type,
        "Tags": [{"Key": "Name", "Value": name}, {"Key": "sim2real", "Value": "true"}],
    }


def _delete_stack(cfn, stack_name: str) -> None:
    _safe(lambda: cfn.delete_stack(StackName=stack_name))
    deadline = time.monotonic() + 900
    status = None
    while time.monotonic() < deadline:
        try:
            status = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
                raise
            return
        if status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} DELETE_FAILED")
        time.sleep(2)
    raise AssertionError(f"stack {stack_name} did not delete within 900s (last status={status})")


def _delete_cluster(eks, cluster_name: str) -> None:
    try:
        eks.delete_cluster(name=cluster_name)
    except eks.exceptions.ResourceNotFoundException:
        return
    deadline = time.monotonic() + 900
    while time.monotonic() < deadline:
        try:
            eks.describe_cluster(name=cluster_name)
        except eks.exceptions.ResourceNotFoundException:
            return
        time.sleep(2)
    raise AssertionError(f"cluster {cluster_name} was not deleted within 900s")


def _delete_role(iam, role_name: str, policy_arns: list[str]) -> None:
    for arn in policy_arns:
        _safe(lambda a=arn: iam.detach_role_policy(RoleName=role_name, PolicyArn=a))
    _safe(lambda: iam.delete_role(RoleName=role_name))


def _create_cluster_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-eks-clrole-")
    trust = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Principal": {"Service": "eks.amazonaws.com"}, "Action": "sts:AssumeRole"}
            ],
        }
    )
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, [policy_arn]))
    _poll_until(
        lambda: iam.list_attached_role_policies(RoleName=role_name)["AttachedPolicies"],
        lambda pols: any(p["PolicyArn"] == policy_arn for p in pols),
        timeout_s=30,
        interval_s=3,
    )
    return role_arn


def _create_pod_identity_target_role(ctx, iam) -> str:
    role_name = ctx.unique_name("sim2real-eks-pidrole-")
    trust = json.dumps(
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust)["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(iam, role_name, []))
    _poll_until(
        lambda: iam.get_role(RoleName=role_name)["Role"],
        lambda r: r["Arn"] == role_arn,
        timeout_s=30,
        interval_s=3,
    )
    return role_arn


def _create_vpc_and_subnets(ctx, ec2) -> list[str]:
    vpc_id = ec2.create_vpc(
        CidrBlock="10.79.0.0/16",
        TagSpecifications=[_tag_spec("vpc", ctx.unique_name("sim2real-eks-vpc-"))],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _safe(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id)))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ]
    az_names = [az["ZoneName"] for az in azs[:2]]
    if len(az_names) < 2:
        raise AssertionError("region does not have at least 2 available AZs for EKS subnets")

    subnet_ids: list[str] = []
    for i, az in enumerate(az_names):
        sid = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.79.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[_tag_spec("subnet", ctx.unique_name(f"sim2real-eks-subnet{i}-"))],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(sid)
        ctx.on_cleanup(lambda sid=sid: _safe(lambda: _delete_net(ec2, "delete_subnet", SubnetId=sid)))

    return subnet_ids


# AWS-managed ENIs (endpoints, load balancers, functions) leave a VPC asynchronously after their
# owner's delete returns, so DeleteSubnet/DeleteSecurityGroup/DeleteVpc can fail with
# DependencyViolation. Wait (bounded) for the ENIs to go, retry inside the same window, and raise
# naming any ENIs still attached. Teardown-only: run() never calls this.
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
