"""cfn-ecs-service-resource-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-ecs-service-resource-lifecycle"
GROUP = "cloudformation"
SERVICES = ["cloudformation", "ec2", "ecs"]

_TEMPLATE = json.dumps(
    {
        "Parameters": {
            "ServiceName": {"Type": "String"},
            "TaskDefinitionArn": {"Type": "String"},
        },
        "Resources": {
            "Vpc": {
                "Type": "AWS::EC2::VPC",
                "Properties": {
                    "CidrBlock": "10.91.0.0/16",
                    "Tags": [{"Key": "sim2real", "Value": "behavioral"}],
                },
            },
            "SubnetA": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": "10.91.1.0/24",
                    "AvailabilityZone": {"Fn::Select": [0, {"Fn::GetAZs": ""}]},
                    "Tags": [{"Key": "sim2real", "Value": "behavioral"}],
                },
            },
            "SubnetB": {
                "Type": "AWS::EC2::Subnet",
                "Properties": {
                    "VpcId": {"Ref": "Vpc"},
                    "CidrBlock": "10.91.2.0/24",
                    "AvailabilityZone": {"Fn::Select": [1, {"Fn::GetAZs": ""}]},
                    "Tags": [{"Key": "sim2real", "Value": "behavioral"}],
                },
            },
            "Sg": {
                "Type": "AWS::EC2::SecurityGroup",
                "Properties": {
                    "GroupDescription": "sim2real cfn-ecs-service-resource-lifecycle",
                    "VpcId": {"Ref": "Vpc"},
                    "Tags": [{"Key": "sim2real", "Value": "behavioral"}],
                },
            },
            "Cluster": {
                "Type": "AWS::ECS::Cluster",
                "Properties": {"Tags": [{"Key": "sim2real", "Value": "behavioral"}]},
            },
            "Service": {
                "Type": "AWS::ECS::Service",
                "Properties": {
                    "Cluster": {"Ref": "Cluster"},
                    "ServiceName": {"Ref": "ServiceName"},
                    "TaskDefinition": {"Ref": "TaskDefinitionArn"},
                    "DesiredCount": 0,
                    "LaunchType": "FARGATE",
                    "NetworkConfiguration": {
                        "AwsvpcConfiguration": {
                            "Subnets": [{"Ref": "SubnetA"}, {"Ref": "SubnetB"}],
                            "SecurityGroups": [{"Ref": "Sg"}],
                            "AssignPublicIp": "DISABLED",
                        }
                    },
                    "Tags": [{"Key": "sim2real", "Value": "behavioral"}],
                },
            },
        },
        "Outputs": {
            "ClusterArn": {"Value": {"Fn::GetAtt": ["Cluster", "Arn"]}},
            "SubnetAId": {"Value": {"Ref": "SubnetA"}},
            "SubnetBId": {"Value": {"Ref": "SubnetB"}},
            "SgId": {"Value": {"Ref": "Sg"}},
            "ServiceGetAttName": {"Value": {"Fn::GetAtt": ["Service", "Name"]}},
            "ServiceGetAttArn": {"Value": {"Fn::GetAtt": ["Service", "ServiceArn"]}},
        },
    }
)


def _wait_stack(cfn, stack_name, waiter_name, max_attempts=300):
    cfn.get_waiter(waiter_name).wait(
        StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": max_attempts}
    )


def _delete_stack_and_wait(cfn, stack_name):
    try:
        cfn.delete_stack(StackName=stack_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise
    try:
        _wait_stack(cfn, stack_name, "stack_delete_complete")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ValidationError":
            raise


def _retire_task_definition(ecs, task_definition_arn):
    """Deregister then delete a task definition revision; an already-gone one is fine."""
    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition_arn)
        described = described["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=task_definition_arn)
    result = ecs.delete_task_definitions(taskDefinitions=[task_definition_arn])
    failures = result.get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {task_definition_arn} teardown failed: {failures}")


@tags(
    "axis:happy-path",
    "cap:c3",
    "cap:c4",
    "concern:deploy",
    "plane:control",
)
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::ECS::Service reads back through DescribeServices with the
    template's properties and every Fn::GetAtt value, then the stack delete leaves it INACTIVE —
    the terminal state ECS documents for a service with no running tasks to drain.
    """
    cfn = ctx.client("cloudformation")
    ecs = ctx.client("ecs")

    family = ctx.unique_name("sim2real-behav-ecstaskdef-")
    task_def = ecs.register_task_definition(
        family=family,
        networkMode="awsvpc",
        requiresCompatibilities=["FARGATE"],
        cpu="256",
        memory="512",
        containerDefinitions=[
            {
                "name": "app",
                "image": "public.ecr.aws/docker/library/busybox:1.36",
                "essential": True,
                "command": ["sleep", "3600"],
            }
        ],
        tags=[{"key": "sim2real", "value": "behavioral"}],
    )
    task_def_arn = task_def["taskDefinition"]["taskDefinitionArn"]
    ctx.on_cleanup(lambda: _retire_task_definition(ecs, task_def_arn))

    stack_name = ctx.unique_name("sim2real-behav-ecssvc-stack-")
    service_name = ctx.unique_name("sim2real-behav-ecssvc-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "ServiceName", "ParameterValue": service_name},
            {"ParameterKey": "TaskDefinitionArn", "ParameterValue": task_def_arn},
        ],
        Tags=[{"Key": "sim2real", "Value": "behavioral"}],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(cfn, stack_name))
    _wait_stack(cfn, stack_name, "stack_create_complete")

    outputs = {
        o["OutputKey"]: o["OutputValue"]
        for o in cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["Outputs"]
    }
    cluster_arn = outputs["ClusterArn"]
    service_physical_id = cfn.describe_stack_resource(
        StackName=stack_name, LogicalResourceId="Service"
    )["StackResourceDetail"]["PhysicalResourceId"]

    described = ecs.describe_services(cluster=cluster_arn, services=[service_physical_id])
    assert not described["failures"], (
        f"DescribeServices reported failures: {described['failures']!r}"
    )
    svc = described["services"][0]

    assert svc["serviceName"] == service_name, (
        f"expected serviceName {service_name!r}, got {svc['serviceName']!r}"
    )
    assert svc["clusterArn"] == cluster_arn, (
        f"expected clusterArn {cluster_arn!r}, got {svc['clusterArn']!r}"
    )
    assert svc["taskDefinition"] == task_def_arn, (
        f"expected taskDefinition {task_def_arn!r}, got {svc['taskDefinition']!r}"
    )
    assert svc["desiredCount"] == 0, f"expected desiredCount 0, got {svc['desiredCount']!r}"
    assert svc["launchType"] == "FARGATE", f"expected launchType FARGATE, got {svc['launchType']!r}"
    assert svc["status"] == "ACTIVE", f"expected status ACTIVE, got {svc['status']!r}"
    net = svc["networkConfiguration"]["awsvpcConfiguration"]
    want_subnets = sorted([outputs["SubnetAId"], outputs["SubnetBId"]])
    assert sorted(net["subnets"]) == want_subnets, (
        f"expected subnets {want_subnets!r}, got {sorted(net['subnets'])!r}"
    )
    assert net["securityGroups"] == [outputs["SgId"]], (
        f"expected securityGroups {[outputs['SgId']]!r}, got {net['securityGroups']!r}"
    )
    assert net["assignPublicIp"] == "DISABLED", (
        f"expected assignPublicIp DISABLED, got {net['assignPublicIp']!r}"
    )

    assert outputs["ServiceGetAttArn"] == service_physical_id, (
        f"Fn::GetAtt Service.ServiceArn {outputs['ServiceGetAttArn']!r} must equal the stack's "
        f"own PhysicalResourceId {service_physical_id!r}"
    )
    assert outputs["ServiceGetAttArn"] == svc["serviceArn"], (
        f"Fn::GetAtt Service.ServiceArn {outputs['ServiceGetAttArn']!r} must equal "
        f"DescribeServices' serviceArn {svc['serviceArn']!r}"
    )
    assert outputs["ServiceGetAttName"] == svc["serviceName"], (
        f"Fn::GetAtt Service.Name {outputs['ServiceGetAttName']!r} must equal "
        f"DescribeServices' serviceName {svc['serviceName']!r}"
    )

    network = _network_ids(cfn, stack_name)
    _delete_stack_and_wait(cfn, stack_name)

    # ECS documents no not-found error for a service with no tasks to drain: DeleteService moves
    # it straight from ACTIVE to the terminal INACTIVE, still readable through DescribeServices.
    redescribed = ecs.describe_services(cluster=cluster_arn, services=[service_physical_id])
    assert not redescribed["failures"], (
        f"DescribeServices reported failures for the deleted service: {redescribed['failures']!r}"
    )
    gone = redescribed["services"][0]
    assert gone["status"] == "INACTIVE", (
        f"a deleted service with no running tasks must read back INACTIVE, got {gone['status']!r}"
    )
    assert gone["desiredCount"] == 0 and gone["runningCount"] == 0, (
        f"a deleted service must carry zero desired and running counts, got "
        f"desiredCount={gone['desiredCount']!r} runningCount={gone['runningCount']!r}"
    )
    clusters = ecs.describe_clusters(clusters=[cluster_arn])
    got_cluster = (clusters["failures"], [(c["clusterArn"], c["status"]) for c in clusters["clusters"]])
    assert got_cluster == ([], [(cluster_arn, "INACTIVE")]), (
        f"the stack's cluster must read back INACTIVE after the stack delete, got {got_cluster!r}"
    )
    _assert_network_gone(ctx.client("ec2"), network)


# What EC2 answers for each network resource the stack created, once the stack delete removed it.
_EC2_GONE = {
    "AWS::EC2::VPC": ("describe_vpcs", "VpcIds", "InvalidVpcID.NotFound", "The vpc ID '{}' does not exist"),
    "AWS::EC2::Subnet": (
        "describe_subnets", "SubnetIds", "InvalidSubnetID.NotFound", "The subnet ID '{}' does not exist"
    ),
    "AWS::EC2::SecurityGroup": (
        "describe_security_groups", "GroupIds", "InvalidGroup.NotFound", "The security group '{}' does not exist"
    ),
}


def _network_ids(cfn, stack: str) -> list[tuple[str, str]]:
    """``(resource type, physical id)`` of every VPC, subnet and security group in the stack."""
    return sorted(
        (r["ResourceType"], r["PhysicalResourceId"])
        for r in cfn.describe_stack_resources(StackName=stack)["StackResources"]
        if r["ResourceType"] in _EC2_GONE
    )


def _assert_network_gone(ec2, network: list[tuple[str, str]]) -> None:
    """Each network resource answers EC2's own not-found code and message."""
    for rtype, physical_id in network:
        op, param, code, message = _EC2_GONE[rtype]
        try:
            found = getattr(ec2, op)(**{param: [physical_id]})
        except ClientError as exc:
            got = (exc.response["Error"]["Code"], exc.response["Error"].get("Message"))
        else:
            raise AssertionError(f"{rtype} {physical_id} still described after the stack delete: {found!r}")
        assert got == (code, message.format(physical_id)), (
            f"{rtype} {physical_id} after the stack delete: {got!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
