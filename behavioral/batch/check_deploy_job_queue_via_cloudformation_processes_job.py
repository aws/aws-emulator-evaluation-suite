"""deploy-job-queue-via-cloudformation-processes-job."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-job-queue-via-cloudformation-processes-job"
GROUP = "deploy"
SERVICES = ["batch"]

_JOB_TERMINAL = {"SUCCEEDED", "FAILED"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A ComputeEnvironment+JobQueue+JobDefinition deployed via CloudFormation actually runs a job."""
    subnet_id, sg_id = _create_network(ctx)
    subnet_ids = [subnet_id]

    ce_name = ctx.unique_name("sim2real-batch-cfn-ce-")
    jq_name = ctx.unique_name("sim2real-batch-cfn-jq-")
    jd_name = ctx.unique_name("sim2real-batch-cfn-jd-")
    role_name = ctx.unique_name("sim2real-batch-cfn-role-")

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "ExecutionRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
                    ],
                },
            },
            "ComputeEnvironment": {
                "Type": "AWS::Batch::ComputeEnvironment",
                "Properties": {
                    "ComputeEnvironmentName": ce_name,
                    "Type": "MANAGED",
                    "ComputeResources": {
                        "Type": "FARGATE",
                        "MaxvCpus": 2,
                        "Subnets": subnet_ids,
                        "SecurityGroupIds": [sg_id],
                    },
                },
            },
            "JobQueue": {
                "Type": "AWS::Batch::JobQueue",
                "Properties": {
                    "JobQueueName": jq_name,
                    "Priority": 1,
                    "State": "ENABLED",
                    "ComputeEnvironmentOrder": [
                        {"Order": 1, "ComputeEnvironment": {"Ref": "ComputeEnvironment"}}
                    ],
                },
            },
            "JobDefinition": {
                "Type": "AWS::Batch::JobDefinition",
                "Properties": {
                    "JobDefinitionName": jd_name,
                    "Type": "container",
                    "PlatformCapabilities": ["FARGATE"],
                    "ContainerProperties": {
                        "Image": "public.ecr.aws/docker/library/busybox:1.36",
                        "Command": ["echo", "hello-from-cfn-batch"],
                        "ExecutionRoleArn": {"Fn::GetAtt": ["ExecutionRole", "Arn"]},
                        "ResourceRequirements": [
                            {"Type": "VCPU", "Value": "0.25"},
                            {"Type": "MEMORY", "Value": "512"},
                        ],
                        "NetworkConfiguration": {"AssignPublicIp": "ENABLED"},
                    },
                },
            },
        },
    }

    _deploy_cfn(ctx, template)

    batch = ctx.client("batch")
    described_jq = _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[jq_name])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
        timeout_s=120,
    )
    assert described_jq["state"] == "ENABLED"

    job = batch.submit_job(
        jobName=ctx.unique_name("sim2real-batch-cfn-job-"),
        jobQueue=jq_name,
        jobDefinition=jd_name,
    )

    final = _poll_until(
        lambda: batch.describe_jobs(jobs=[job["jobId"]])["jobs"][0],
        lambda j: j["status"] in _JOB_TERMINAL,
        timeout_s=540,
        interval_s=5,
    )
    assert final["status"] == "SUCCEEDED", (
        f"job deployed via CloudFormation never ran to completion: {final['status']} "
        f"({final.get('statusReason')})"
    )


def _create_network(ctx) -> tuple[str, str]:
    """(subnet_id, security_group_id) in an internet-routable VPC this check creates and tears down.

    The check owns its networking: a VPC, one public subnet, an internet gateway with a default
    route (so a Fargate task can pull a public image), and the VPC's own default security group.
    """
    ec2 = ctx.client("ec2")
    vpc_id = ec2.create_vpc(CidrBlock="10.182.0.0/16")["Vpc"]["VpcId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_vpc(VpcId=vpc_id)))
    ec2.create_tags(Resources=[vpc_id], Tags=[{"Key": "Name", "Value": ctx.unique_name("sim2real-batch-vpc-")}])
    ec2.get_waiter("vpc_available").wait(VpcIds=[vpc_id], WaiterConfig={"Delay": 2, "MaxAttempts": 300})
    az = ec2.describe_availability_zones(Filters=[{"Name": "state", "Values": ["available"]}])[
        "AvailabilityZones"
    ][0]["ZoneName"]
    subnet_id = ec2.create_subnet(VpcId=vpc_id, CidrBlock="10.182.1.0/24", AvailabilityZone=az)["Subnet"][
        "SubnetId"
    ]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_subnet(SubnetId=subnet_id)))
    ec2.modify_subnet_attribute(SubnetId=subnet_id, MapPublicIpOnLaunch={"Value": True})
    igw_id = ec2.create_internet_gateway()["InternetGateway"]["InternetGatewayId"]
    ctx.on_cleanup(lambda: _delete_with_retry(lambda: ec2.delete_internet_gateway(InternetGatewayId=igw_id)))
    ec2.attach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
    ctx.on_cleanup(
        lambda: _delete_with_retry(lambda: ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id))
    )
    rt_id = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])["RouteTables"][0][
        "RouteTableId"
    ]
    ec2.create_route(RouteTableId=rt_id, DestinationCidrBlock="0.0.0.0/0", GatewayId=igw_id)
    sg_id = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"][0]["GroupId"]
    return subnet_id, sg_id


def _delete_with_retry(fn, timeout_s: float = 600.0) -> None:
    """Retry a network delete while Fargate/Batch ENIs drain (DependencyViolation)."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code.endswith(".NotFound") or code in ("Gateway.NotAttached",):
                return
            if code != "DependencyViolation" or time.monotonic() > deadline:
                raise
            time.sleep(15)


def _poll_until(probe, predicate, timeout_s=90.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


def _deploy_cfn(ctx, template_dict):
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-batch-cfn-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template_dict),
        Capabilities=["CAPABILITY_NAMED_IAM"],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    waiter = cfn.get_waiter("stack_create_complete")
    waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})
    return stack_name


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
        waiter = cfn.get_waiter("stack_delete_complete")
        waiter.wait(StackName=stack_name, WaiterConfig={"Delay": 2, "MaxAttempts": 450})
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "StackNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
