"""deploy-compute-environment-cloudformation-behaves."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-compute-environment-cloudformation-behaves"
GROUP = "deploy"
SERVICES = ["batch"]

_NON_TERMINAL = {"SUBMITTED", "PENDING", "RUNNABLE", "SCHEDULED", "STARTING", "RUNNING"}


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack of Batch scheduling policy, service environment, job queue and quota share completes.

    The queue is VALID/ENABLED and runs a service job submitted to its quota share to SUCCEEDED.
    """
    cfn = ctx.client("cloudformation")
    batch = ctx.client("batch")

    role_arn = _create_sagemaker_role(ctx)
    bucket = _create_output_bucket(ctx)

    sp_name = ctx.unique_name("sim2real-batch-cfn-sp-")
    senv_name = ctx.unique_name("sim2real-batch-cfn-senv-")
    jq_name = ctx.unique_name("sim2real-batch-cfn-jq-")
    qs_name = ctx.unique_name("sim2real-batch-cfn-qs-")
    stack_name = ctx.unique_name("sim2real-batch-cfn-stack-")

    # Quota shares attach only to SAGEMAKER_TRAINING queues, hence a service environment as compute.
    template = _build_template(sp_name, senv_name, jq_name, qs_name)
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _teardown_stack(ctx, stack_name, jq_name, qs_name, senv_name))

    stack = _wait_for(
        lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0],
        lambda s: s["StackStatus"] in ("CREATE_COMPLETE", "ROLLBACK_COMPLETE", "CREATE_FAILED"),
        timeout_s=300,
        interval_s=5,
    )
    assert stack["StackStatus"] == "CREATE_COMPLETE", f"stack did not reach CREATE_COMPLETE: {stack}"

    jq = batch.describe_job_queues(jobQueues=[jq_name])["jobQueues"][0]
    assert jq["status"] == "VALID", f"expected job queue status VALID, got {jq['status']!r}"
    assert jq["state"] == "ENABLED", f"expected job queue state ENABLED, got {jq['state']!r}"

    training_job_name = ctx.unique_name("sim2real-batch-cfn-tj-")
    payload = {
        "TrainingJobName": training_job_name,
        "RoleArn": role_arn,
        "AlgorithmSpecification": {
            "TrainingInputMode": "File",
            "TrainingImage": f"763104351884.dkr.ecr.{ctx.region}.amazonaws.com/pytorch-training:2.0.0-cpu-py310",
            "ContainerEntrypoint": ["echo", "hello from a cloudformation-deployed queue"],
        },
        "ResourceConfig": {"InstanceType": "ml.m6i.large", "InstanceCount": 1, "VolumeSizeInGB": 1},
        "OutputDataConfig": {"S3OutputPath": f"s3://{bucket}/output"},
        "StoppingCondition": {"MaxRuntimeInSeconds": 60},
    }

    job_name = ctx.unique_name("sim2real-batch-cfn-sj-")
    submitted = _submit_service_job_with_retry(
        batch,
        jobName=job_name,
        jobQueue=jq_name,
        serviceJobType="SAGEMAKER_TRAINING",
        serviceRequestPayload=json.dumps(payload),
        quotaShareName=qs_name,
        schedulingPriority=5,
    )
    job_id = submitted["jobId"]

    final = _wait_for(
        lambda: batch.describe_service_job(jobId=job_id),
        lambda d: d["status"] not in _NON_TERMINAL,
        timeout_s=600,
        interval_s=5,
    )
    assert final["status"] == "SUCCEEDED", (
        f"expected the CFN-deployed queue to run the job to SUCCEEDED, got {final['status']!r} "
        f"({final.get('statusReason')!r})"
    )


def _wait_for(probe, predicate, *, timeout_s=90.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _build_template(sp_name, senv_name, jq_name, qs_name):
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "SchedPolicy": {
                "Type": "AWS::Batch::SchedulingPolicy",
                "Properties": {
                    "Name": sp_name,
                    "QuotaSharePolicy": {"IdleResourceAssignmentStrategy": "FIFO"},
                },
            },
            "ServiceEnv": {
                "Type": "AWS::Batch::ServiceEnvironment",
                "Properties": {
                    "ServiceEnvironmentName": senv_name,
                    "ServiceEnvironmentType": "SAGEMAKER_TRAINING",
                    "CapacityLimits": [{"CapacityUnit": "ml.m6i.large", "MaxCapacity": 10}],
                },
            },
            "JQueue": {
                "Type": "AWS::Batch::JobQueue",
                "Properties": {
                    "JobQueueName": jq_name,
                    "JobQueueType": "SAGEMAKER_TRAINING",
                    "Priority": 1,
                    "SchedulingPolicyArn": {"Ref": "SchedPolicy"},
                    "ServiceEnvironmentOrder": [
                        {"Order": 1, "ServiceEnvironment": {"Ref": "ServiceEnv"}}
                    ],
                },
                "DependsOn": ["ServiceEnv", "SchedPolicy"],
            },
            "QShare": {
                "Type": "AWS::Batch::QuotaShare",
                "Properties": {
                    "QuotaShareName": qs_name,
                    "JobQueue": {"Ref": "JQueue"},
                    "CapacityLimits": [{"CapacityUnit": "ml.m6i.large", "MaxCapacity": 5}],
                    "ResourceSharingConfiguration": {"Strategy": "RESERVE"},
                    "PreemptionConfiguration": {"InSharePreemption": "DISABLED"},
                },
                "DependsOn": ["JQueue"],
            },
        },
    }


def _teardown_stack(ctx, stack_name, jq_name, qs_name, senv_name):
    batch = ctx.client("batch")
    cfn = ctx.client("cloudformation")
    # Quota shares and job queues must be DISABLED before they can be deleted; CloudFormation's
    # DeleteStack does not do this for us, so drain the resources first.
    try:
        shares = batch.list_quota_shares(jobQueue=jq_name)["quotaShares"]
        for share in shares:
            if share["quotaShareName"] == qs_name:
                batch.update_quota_share(quotaShareArn=share["quotaShareArn"], state="DISABLED")
                _wait_for(
                    lambda arn=share["quotaShareArn"]: batch.describe_quota_share(quotaShareArn=arn),
                    lambda d: d["status"] == "VALID" and d["state"] == "DISABLED",
                    timeout_s=60,
                )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (
            err["Code"] == "ClientException"
            and any(f in err.get("Message", "") for f in ("does not exist", "not found for update"))
        ):
            raise
    try:
        batch.update_job_queue(jobQueue=jq_name, state="DISABLED")
        _wait_for(
            lambda: batch.describe_job_queues(jobQueues=[jq_name])["jobQueues"][0],
            lambda jq: jq["status"] == "VALID" and jq["state"] == "DISABLED",
            timeout_s=60,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    try:
        batch.update_service_environment(serviceEnvironment=senv_name, state="DISABLED")
        _wait_for(
            lambda: batch.describe_service_environments(serviceEnvironments=[senv_name])["serviceEnvironments"][0],
            lambda se: se["status"] == "VALID" and se["state"] == "DISABLED",
            timeout_s=60,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if not (err["Code"] == "ClientException" and "does not exist" in err.get("Message", "")):
            raise
    try:
        cfn.delete_stack(StackName=stack_name)
        _wait_for(
            lambda: cfn.describe_stacks(StackName=stack_name)["Stacks"][0],
            lambda s: s["StackStatus"] == "DELETE_COMPLETE",
            timeout_s=300,
            interval_s=5,
        )
    except ClientError as exc:
        err = exc.response["Error"]
        if err["Code"] != "StackNotFoundException" and not (
            err["Code"] == "ValidationError" and "does not exist" in err.get("Message", "")
        ):
            raise


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-batch-cfn-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    created = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = created["Role"]["Arn"]
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _create_output_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-batch-cfn-out-").lower()
    if ctx.region == "us-east-1":  # S3 CreateBucket rejects an explicit LocationConstraint here
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            for obj in objs:
                s3.delete_object(Bucket=bucket, Key=obj["Key"])
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _submit_service_job_with_retry(batch, *, attempts=6, delay_s=10.0, **kwargs):
    last_err = None
    for _ in range(attempts):
        try:
            return batch.submit_service_job(**kwargs)
        except ClientError as err:
            last_err = err
            if err.response["Error"]["Code"] != "ClientException":
                raise
            time.sleep(delay_s)
    raise AssertionError(f"submit_service_job never succeeded after retries: {last_err}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
