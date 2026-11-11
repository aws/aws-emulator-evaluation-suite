"""deploy-addon-via-cloudformation-installed."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-addon-via-cloudformation-installed"
GROUP = "deploy"
SERVICES = ["eks"]

_TAGS = {"sim2real:managed": "true"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:deploy", "plane:control")
def run(ctx) -> None:
    """An AWS::EKS::Addon deployed via CloudFormation reaches ACTIVE with a resolved addonVersion
    in DescribeAddon and is listed by ListAddons; ResolveConflicts is write-only, so it is not
    asserted."""
    ec2 = ctx.client("ec2")
    iam = ctx.client("iam")
    eks = ctx.client("eks")
    cfn = ctx.client("cloudformation")

    subnet_ids = _create_vpc_and_subnets(ctx, ec2, count=2)
    cluster_role_arn = _create_iam_role(
        ctx, iam, "eks.amazonaws.com", ["arn:aws:iam::aws:policy/AmazonEKSClusterPolicy"]
    )

    cluster_name = ctx.unique_name("sim2real-eks-addon-")
    _create_cluster(ctx, eks, cluster_name, cluster_role_arn, subnet_ids)
    _wait_cluster_active(eks, cluster_name)

    addon_name = "vpc-cni"
    stack_name = ctx.unique_name("sim2real-eks-addon-stack-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Addon": {
                "Type": "AWS::EKS::Addon",
                "Properties": {
                    "ClusterName": cluster_name,
                    "AddonName": addon_name,
                    "ResolveConflicts": "OVERWRITE",
                },
            }
        },
    }

    def _delete_stack():
        cfn.delete_stack(StackName=stack_name)
        cfn.get_waiter("stack_delete_complete").wait(
            StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
        )

    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )

    ctx.on_cleanup(_delete_stack)

    cfn.get_waiter("stack_create_complete").wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 600}
    )

    stack = cfn.describe_stacks(StackName=stack_name)["Stacks"][0]
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"expected stack {stack_name} in CREATE_COMPLETE, got {stack['StackStatus']!r}"
    )

    described = eks.describe_addon(clusterName=cluster_name, addonName=addon_name)["addon"]
    assert described["status"] == "ACTIVE", (
        f"expected addon {addon_name} ACTIVE via DescribeAddon, got {described['status']!r}"
    )
    assert described.get("addonVersion"), (
        f"expected DescribeAddon to report a resolved addonVersion, got {described.get('addonVersion')!r}"
    )

    names = eks.list_addons(clusterName=cluster_name)["addons"]
    assert addon_name in names, (
        f"expected {addon_name!r} in ListAddons at the cluster, got {names!r}"
    )


# ===== helpers =====
def _create_vpc_and_subnets(ctx, ec2, count=2):
    """Provision a dedicated VPC + AZ-distinct subnets rather than depending on an
    ambient default VPC, which a freshly provisioned account may not have."""
    tag_specs = [{"Key": k, "Value": v} for k, v in _TAGS.items()]
    vpc_id = ec2.create_vpc(
        CidrBlock="10.71.0.0/16",
        TagSpecifications=[{"ResourceType": "vpc", "Tags": tag_specs}],
    )["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_net(ec2, "delete_vpc", VpcId=vpc_id))
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsSupport={"Value": True})
    ec2.modify_vpc_attribute(VpcId=vpc_id, EnableDnsHostnames={"Value": True})

    azs = [
        a["ZoneName"]
        for a in ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
            "AvailabilityZones"
        ]
    ]
    if len(azs) < count:
        raise AssertionError(f"region has only {len(azs)} available AZs, need {count} for an EKS cluster")

    subnet_ids = []
    for i, az in enumerate(azs[:count]):
        subnet_id = ec2.create_subnet(
            VpcId=vpc_id,
            CidrBlock=f"10.71.{i}.0/24",
            AvailabilityZone=az,
            TagSpecifications=[{"ResourceType": "subnet", "Tags": tag_specs}],
        )["Subnet"]["SubnetId"]
        subnet_ids.append(subnet_id)
        ctx.on_cleanup(lambda subnet_id=subnet_id: _delete_net(ec2, "delete_subnet", SubnetId=subnet_id))
    return subnet_ids


def _create_iam_role(ctx, iam, trust_service, managed_policy_arns):
    role_name = ctx.unique_name("sim2real-eks-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": k, "Value": v} for k, v in _TAGS.items()],
    )["Role"]
    for arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)

    def _cleanup():
        for arn in managed_policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role["Arn"]


def _create_cluster(ctx, eks, cluster_name, role_arn, subnet_ids):
    def _cleanup():
        eks.delete_cluster(name=cluster_name)
        _wait_cluster_deleted(eks, cluster_name)

    ctx.on_cleanup(_cleanup)
    deadline = time.monotonic() + 30
    last_err = None
    while time.monotonic() < deadline:
        try:
            eks.create_cluster(
                name=cluster_name,
                roleArn=role_arn,
                resourcesVpcConfig={"subnetIds": subnet_ids},
                tags=_TAGS,
            )
            return
        except ClientError as exc:  # pragma: no cover - transient IAM propagation
            last_err = exc
            time.sleep(3)
    raise AssertionError(f"CreateCluster never succeeded (role propagation?): {last_err}")


def _wait_cluster_active(eks, cluster_name):
    eks.get_waiter("cluster_active").wait(
        name=cluster_name, WaiterConfig={"Delay": 2, "MaxAttempts": 900}
    )


def _wait_cluster_deleted(eks, cluster_name):
    eks.get_waiter("cluster_deleted").wait(
        name=cluster_name, WaiterConfig={"Delay": 2, "MaxAttempts": 300}
    )


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
