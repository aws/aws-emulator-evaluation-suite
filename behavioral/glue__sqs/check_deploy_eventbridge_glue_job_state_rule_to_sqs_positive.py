"""deploy-eventbridge-glue-job-state-rule-to-sqs-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deploy-eventbridge-glue-job-state-rule-to-sqs-positive"
GROUP = "deployment-order"
SERVICES = ["glue", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN-deployed EventBridge rule matching 'Glue Job State Change' delivers the real
    SUCCEEDED event emitted by a Glue job run to an SQS queue, end-to-end, once the queue's
    resource policy grants events.amazonaws.com permission."""
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket_name = _xname(ctx, "bkt")
    queue_name = _xname(ctx, "evq")
    role_name = _xname(ctx, "role")
    job_name = _xname(ctx, "job")
    rule_name = _xname(ctx, "rule")
    rule_arn = f"arn:aws:events:{ctx.region}:{account_id}:rule/{rule_name}"

    template = _build_template(bucket_name, queue_name, role_name, job_name, rule_name, rule_arn)
    stack = _deploy_cfn(ctx, json.dumps(template))
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))

    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    ctx.client("sqs")
    queue_url = stack["outputs"]["QueueUrl"]

    s3.put_object(Bucket=bucket_name, Key="script.py", Body=b'print("ok")\n')

    run_id = glue.start_job_run(JobName=job_name)["JobRunId"]
    job_run = _wait_for_job_run(ctx, job_name, run_id, timeout_s=600.0)
    assert job_run["JobRunState"] == "SUCCEEDED", job_run

    message = _poll_for_matching_message(
        ctx,
        queue_url,
        lambda body: body.get("source") == "aws.glue"
        and body.get("detail-type") == "Glue Job State Change"
        and body.get("detail", {}).get("jobName") == job_name
        and body.get("detail", {}).get("state") == "SUCCEEDED",
        timeout_s=120.0,
    )
    assert message is not None, "expected the Glue Job State Change SUCCEEDED event on the queue"
    assert message["detail"]["jobName"] == job_name, (
        f"expected jobName={job_name!r} on the delivered event, got {message['detail'].get('jobName')!r}"
    )
    assert message["detail"]["state"] == "SUCCEEDED", (
        f"expected state=SUCCEEDED on the delivered event, got {message['detail'].get('state')!r}"
    )
    assert message["detail"]["jobRunId"] == run_id, (
        f"expected the delivered event to correlate to this run (jobRunId={run_id!r}), "
        f"got {message['detail'].get('jobRunId')!r}"
    )


def _build_template(bucket_name, queue_name, role_name, job_name, rule_name, rule_arn) -> dict[str, Any]:
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "TargetQueue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue_name}},
            "TargetQueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "TargetQueue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["TargetQueue", "Arn"]},
                                "Condition": {"ArnEquals": {"aws:SourceArn": rule_arn}},
                            }
                        ],
                    },
                },
            },
            "JobStateRule": {
                "Type": "AWS::Events::Rule",
                "DependsOn": "TargetQueuePolicy",
                "Properties": {
                    "Name": rule_name,
                    "EventPattern": {
                        "source": ["aws.glue"],
                        "detail-type": ["Glue Job State Change"],
                        "detail": {"jobName": [job_name], "state": ["SUCCEEDED"]},
                    },
                    "Targets": [{"Id": "sqs-target", "Arn": {"Fn::GetAtt": ["TargetQueue", "Arn"]}}],
                },
            },
            "ScriptBucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket_name}},
            "JobRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
                    "RoleName": role_name,
                    "AssumeRolePolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "glue.amazonaws.com"},
                                "Action": "sts:AssumeRole",
                            }
                        ],
                    },
                    "ManagedPolicyArns": ["arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"],
                    "Policies": [
                        {
                            "PolicyName": "script-bucket-read",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:GetObject", "s3:ListBucket"],
                                        "Resource": [bucket_arn, f"{bucket_arn}/*"],
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "Job": {
                "Type": "AWS::Glue::Job",
                "DependsOn": ["ScriptBucket", "JobRole"],
                "Properties": {
                    "Name": job_name,
                    "Role": {"Fn::GetAtt": ["JobRole", "Arn"]},
                    "GlueVersion": "3.0",
                    "MaxCapacity": 0.0625,
                    "Command": {
                        "Name": "pythonshell",
                        "PythonVersion": "3.9",
                        "ScriptLocation": f"s3://{bucket_name}/script.py",
                    },
                },
            },
        },
        "Outputs": {"QueueUrl": {"Value": {"Ref": "TargetQueue"}}},
    }


_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


def _xsvc_resource_tags() -> dict[str, str]:
    return {_MANAGED_TAG_KEY: "true", "sim2real:prefix": _XSVC_PREFIX.rstrip("-")}


def _xsvc_tags_kv() -> list[dict[str, str]]:
    return [{"Key": k, "Value": v} for k, v in _xsvc_resource_tags().items()]


def _xname(ctx: Any, kind: str) -> str:
    return ctx.unique_name(f"{_XSVC_PREFIX}{kind}-")


def _delete_stack_and_wait(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)

    def _status():
        try:
            return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("StackNotFoundException", "ValidationError"):
                raise
            return 'GONE'

    _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "GONE"},
        timeout_s=120,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )


def _deploy_cfn(ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0) -> dict[str, Any]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    template_body = template.read_text() if isinstance(template, Path) else template
    kwargs: dict[str, Any] = {
        "StackName": name,
        "TemplateBody": template_body,
        "Tags": _xsvc_tags_kv(),
        "Capabilities": capabilities or ["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    }
    if parameters:
        kwargs["Parameters"] = [{"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _wait_for_job_run(ctx, job_name: str, run_id: str, timeout_s: float = 600.0) -> dict[str, Any]:
    glue = ctx.client("glue")
    return _poll_until(
        lambda: glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"],
        lambda r: r["JobRunState"] in {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"},
        timeout_s=timeout_s,
        interval_s=10.0,
        description=f"job run {run_id} reaching a terminal state",
    )


def _poll_for_matching_message(ctx, queue_url: str, predicate, timeout_s: float = 120.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=5)
        for msg in resp.get("Messages", []):
            try:
                body = json.loads(msg["Body"])
            except (json.JSONDecodeError, ValueError):
                body = None
            if body is not None and predicate(body):
                sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=msg["ReceiptHandle"])
                return body
    return None


def _empty_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        while True:
            resp = s3.list_objects_v2(Bucket=bucket_name)
            contents = resp.get("Contents", [])
            if not contents:
                break
            failed = s3.delete_objects(Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in contents]}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            if not resp.get("IsTruncated"):
                break
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
