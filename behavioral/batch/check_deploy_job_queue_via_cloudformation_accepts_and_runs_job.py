"""deploy-job-queue-via-cloudformation-accepts-and-runs-job."""
from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "deploy-job-queue-via-cloudformation-accepts-and-runs-job"
GROUP = "deploy"
SERVICES = ["batch"]

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-batch-deploy"}

_TEMPLATE = """AWSTemplateFormatVersion: '2010-09-09'
Parameters:
  SubnetIds:
    Type: CommaDelimitedList
  SecurityGroupIds:
    Type: CommaDelimitedList
Resources:
  BatchServiceRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: batch.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AWSBatchServiceRole
      Tags:
        - Key: sim2real:managed
          Value: 'true'
        - Key: sim2real:prefix
          Value: sim2real-batch-deploy
  EcsInstanceRole:
    Type: AWS::IAM::Role
    Properties:
      AssumeRolePolicyDocument:
        Version: '2012-10-17'
        Statement:
          - Effect: Allow
            Principal:
              Service: ec2.amazonaws.com
            Action: sts:AssumeRole
      ManagedPolicyArns:
        - arn:aws:iam::aws:policy/service-role/AmazonEC2ContainerServiceforEC2Role
      Tags:
        - Key: sim2real:managed
          Value: 'true'
        - Key: sim2real:prefix
          Value: sim2real-batch-deploy
  EcsInstanceProfile:
    Type: AWS::IAM::InstanceProfile
    Properties:
      Roles:
        - !Ref EcsInstanceRole
  BatchComputeEnvironment:
    Type: AWS::Batch::ComputeEnvironment
    Properties:
      Type: MANAGED
      ServiceRole: !GetAtt BatchServiceRole.Arn
      ComputeResources:
        Type: EC2
        MinvCpus: 0
        MaxvCpus: 2
        InstanceRole: !GetAtt EcsInstanceProfile.Arn
        InstanceTypes:
          - optimal
        Subnets: !Ref SubnetIds
        SecurityGroupIds: !Ref SecurityGroupIds
      Tags:
        sim2real:managed: 'true'
        sim2real:prefix: sim2real-batch-deploy
  BatchJobQueue:
    Type: AWS::Batch::JobQueue
    Properties:
      Priority: 1
      ComputeEnvironmentOrder:
        - Order: 1
          ComputeEnvironment: !Ref BatchComputeEnvironment
      Tags:
        sim2real:managed: 'true'
        sim2real:prefix: sim2real-batch-deploy
Outputs:
  ComputeEnvironmentArn:
    Value: !Ref BatchComputeEnvironment
  JobQueueArn:
    Value: !Ref BatchJobQueue
"""


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed job queue and managed EC2 compute environment run a submitted job.

    The job is tracked in GetJobQueueSnapshot while pending and moves past RUNNABLE to RUNNING/SUCCEEDED.
    """
    ec2 = ctx.client("ec2")
    cfn = ctx.client("cloudformation")
    batch = ctx.client("batch")

    vpcs = ec2.describe_vpcs(Filters=[{"Name": "vpc-id", "Values": [ctx.network().vpc_id]}])["Vpcs"]
    if not vpcs:

        raise AssertionError("no shared network VPC available to network the compute environment")
    vpc_id = vpcs[0]["VpcId"]
    subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "subnet-id", "Values": ctx.network().subnet_ids}])["Subnets"]
    if not subnets:
        raise AssertionError("shared network has no subnets to place the compute environment in")
    subnet_ids = [s["SubnetId"] for s in subnets[:2]]
    sgs = ec2.describe_security_groups(
        Filters=[{"Name": "vpc-id", "Values": [vpc_id]}, {"Name": "group-name", "Values": ["default"]}]
    )["SecurityGroups"]
    if not sgs:
        raise AssertionError("shared network has no default security group")
    sg_ids = [sgs[0]["GroupId"]]

    stack_name = ctx.unique_name("sim2real-batch-deploy-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=_TEMPLATE,
        Parameters=[
            {"ParameterKey": "SubnetIds", "ParameterValue": ",".join(subnet_ids)},
            {"ParameterKey": "SecurityGroupIds", "ParameterValue": ",".join(sg_ids)},
        ],
        Capabilities=["CAPABILITY_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))

    stack = _poll_until(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0],
        lambda s: s["StackStatus"] in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert stack["StackStatus"] == "CREATE_COMPLETE", (
        f"stack did not reach CREATE_COMPLETE: {stack['StackStatus']}"
    )
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack["Outputs"]}
    jq_arn = outputs["JobQueueArn"]

    _poll_until(
        lambda: batch.describe_job_queues(jobQueues=[jq_arn])["jobQueues"][0],
        lambda jq: jq["status"] == "VALID",
        timeout_s=120.0,
    )

    jd_name = ctx.unique_name("sim2real-batch-deploy-jd-")
    reg = batch.register_job_definition(
        jobDefinitionName=jd_name,
        type="container",
        containerProperties={
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "command": ["echo", "hello-from-cfn-deployed-batch"],
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "512"},
            ],
        },
        tags=_MANAGED_TAGS,
    )
    jd_arn = reg["jobDefinitionArn"]
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=jd_arn))

    submitted = batch.submit_job(
        jobName=ctx.unique_name("sim2real-batch-deploy-job-"),
        jobQueue=jq_arn,
        jobDefinition=jd_arn,
        tags=_MANAGED_TAGS,
    )
    job_id = submitted["jobId"]
    job_arn = submitted["jobArn"]
    ctx.on_cleanup(lambda: _terminate_and_wait(ctx, job_id))

    # Confirm the CFN-deployed queue actually tracks the job for dispatch, not just accepts it.
    _poll_until(
        lambda: batch.get_job_queue_snapshot(jobQueue=jq_arn),
        lambda snap: job_arn in [j["jobArn"] for j in snap.get("frontOfQueue", {}).get("jobs", [])],
        timeout_s=90.0,
        interval_s=3.0,
    )

    def _describe_job() -> dict[str, Any]:
        return batch.describe_jobs(jobs=[job_id])["jobs"][0]

    final = _poll_until(
        _describe_job,
        lambda j: j["status"] in ("RUNNING", "SUCCEEDED", "FAILED"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert final["status"] != "FAILED", f"job failed instead of running: {final.get('statusReason')}"
    assert final["status"] in ("RUNNING", "SUCCEEDED"), (
        f"expected job to progress to RUNNING or SUCCEEDED, got {final['status']!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=5.0) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last value={last!r}")


def _terminate_and_wait(ctx, job_id: str) -> None:
    batch = ctx.client("batch")
    batch.terminate_job(jobId=job_id, reason="sim2real-behavioral-cleanup")
    _poll_until(
        lambda: batch.describe_jobs(jobs=[job_id])["jobs"][0],
        lambda j: j["status"] in ("SUCCEEDED", "FAILED"),
        timeout_s=120.0,
        interval_s=5.0,
    )


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    try:
        cfn.delete_stack(StackName=stack_name)
        _poll_until(
            lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"],
            lambda status: status == "DELETE_COMPLETE",
            timeout_s=600.0,
            interval_s=10.0,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] != "StackNotFoundException" and not (
            err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
        ):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
