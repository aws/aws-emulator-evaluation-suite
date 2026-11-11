"""cfn-deploy-glue-job-eventbridge-sqs-stack-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cfn-deploy-glue-job-eventbridge-sqs-stack-positive"
GROUP = "deployment-order"
SERVICES = ["glue", "sqs"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CFN stack wiring a Glue job's completion events through EventBridge to an SQS
    queue actually delivers a "Glue Job State Change" / SUCCEEDED notification once the
    real Glue job run finishes."""
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    script_key = "job_script.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=b"print('hello-from-glue-job')\n")

    job_name = _xname(ctx, "job")
    template = json.dumps(_job_template())
    stack = _deploy_cfn(
        ctx,
        template,
        parameters={
            "JobName": job_name,
            "ScriptBucket": bucket,
            "ScriptKey": script_key,
        },
    )
    queue_url = stack["outputs"]["QueueUrl"]

    glue = ctx.client("glue")
    run_id = glue.start_job_run(JobName=job_name)["JobRunId"]

    def _job_state():
        return glue.get_job_run(JobName=job_name, RunId=run_id)["JobRun"]["JobRunState"]

    final_state = _poll_until(
        _job_state,
        lambda s: s in {"SUCCEEDED", "FAILED", "STOPPED", "TIMEOUT", "ERROR"},
        timeout_s=420.0,
        interval_s=10.0,
        description=f"glue job run {run_id} reach terminal state",
    )
    assert final_state == "SUCCEEDED", f"job run ended in {final_state}"

    message = _wait_for_matching_message(
        ctx,
        queue_url,
        lambda body: (
            isinstance(body, dict)
            and body.get("detail-type") == "Glue Job State Change"
            and body.get("detail", {}).get("jobName") == job_name
            and body.get("detail", {}).get("state") == "SUCCEEDED"
        ),
        timeout_s=180.0,
    )
    assert message["source"] == "aws.glue", f"expected source aws.glue, got {message.get('source')!r}"
    assert message["detail"]["jobRunId"] == run_id, (
        f"expected jobRunId {run_id!r} on the delivered event, got {message['detail'].get('jobRunId')!r}"
    )


def _job_template() -> dict[str, Any]:
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "JobName": {"Type": "String"},
            "ScriptBucket": {"Type": "String"},
            "ScriptKey": {"Type": "String"},
        },
        "Resources": {
            "GlueRole": {
                "Type": "AWS::IAM::Role",
                "Properties": {
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
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
                    ],
                    "Policies": [
                        {
                            "PolicyName": "ScriptAccess",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:GetObject"],
                                        "Resource": {
                                            "Fn::Sub": "arn:aws:s3:::${ScriptBucket}/${ScriptKey}"
                                        },
                                    }
                                ],
                            },
                        }
                    ],
                },
            },
            "GlueJob": {
                "Type": "AWS::Glue::Job",
                "Properties": {
                    "Name": {"Ref": "JobName"},
                    "Role": {"Fn::GetAtt": ["GlueRole", "Arn"]},
                    "Command": {
                        "Name": "pythonshell",
                        "PythonVersion": "3.9",
                        "ScriptLocation": {"Fn::Sub": "s3://${ScriptBucket}/${ScriptKey}"},
                    },
                    "MaxCapacity": 0.0625,
                    "GlueVersion": "3.0",
                    "Timeout": 5,
                },
            },
            "EventQueue": {"Type": "AWS::SQS::Queue"},
            "EventRule": {
                "Type": "AWS::Events::Rule",
                "Properties": {
                    "EventPattern": {
                        "source": ["aws.glue"],
                        "detail-type": ["Glue Job State Change"],
                        "detail": {"jobName": [{"Ref": "JobName"}]},
                    },
                    "State": "ENABLED",
                    "Targets": [
                        {"Id": "sqs-target", "Arn": {"Fn::GetAtt": ["EventQueue", "Arn"]}}
                    ],
                },
            },
            "EventQueuePolicy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "EventQueue"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "events.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["EventQueue", "Arn"]},
                                "Condition": {
                                    "ArnEquals": {
                                        "aws:SourceArn": {"Fn::GetAtt": ["EventRule", "Arn"]}
                                    }
                                },
                            }
                        ],
                    },
                },
            },
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "EventQueue"}},
            "QueueArn": {"Value": {"Fn::GetAtt": ["EventQueue", "Arn"]}},
            "RuleArn": {"Value": {"Fn::GetAtt": ["EventRule", "Arn"]}},
        },
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


def _deploy_cfn(
    ctx, template, *, stack_name=None, parameters=None, capabilities=None, timeout_s=300.0
) -> dict[str, Any]:
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
        kwargs["Parameters"] = [
            {"ParameterKey": k, "ParameterValue": v} for k, v in parameters.items()
        ]
    stack_id = cfn.create_stack(**kwargs)["StackId"]
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s
        in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = _xname(ctx, "bucket").lower()
    kwargs: dict[str, Any] = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": _xsvc_tags_kv()})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


def _wait_for_matching_message(ctx, queue_url, predicate, *, timeout_s=180.0):
    sqs = ctx.client("sqs")
    deadline = time.monotonic() + timeout_s
    seen: list[Any] = []
    while time.monotonic() < deadline:
        resp = sqs.receive_message(
            QueueUrl=queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=10
        )
        for m in resp.get("Messages", []):
            try:
                body = json.loads(m["Body"])
            except (json.JSONDecodeError, ValueError):
                body = m["Body"]
            seen.append(body)
            sqs.delete_message(QueueUrl=queue_url, ReceiptHandle=m["ReceiptHandle"])
            if predicate(body):
                return body
    raise AssertionError(f"no message matched within {timeout_s}s; saw {len(seen)}: {seen!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
