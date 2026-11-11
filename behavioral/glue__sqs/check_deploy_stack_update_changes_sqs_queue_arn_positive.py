"""deploy-stack-update-changes-sqs-queue-arn-positive."""
from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deploy-stack-update-changes-sqs-queue-arn-positive"
GROUP = "deployment-order"
SERVICES = ["glue", "sqs"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """A stack update pointing the notification and crawler at a second queue rewires events:
    a post-update S3 event is consumed on the new queue and the original queue never receives it."""
    bucket_name = _xname(ctx, "bkt")
    queue1_name = _xname(ctx, "evq1")
    queue2_name = _xname(ctx, "evq2")
    role_name = _xname(ctx, "role")
    db_name = _xname(ctx, "db").replace("-", "_")
    crawler_name = _xname(ctx, "crawler")

    template_v1 = _build_template(bucket_name, queue1_name, queue2_name, role_name, db_name, crawler_name, active="Queue1")
    stack = _deploy_cfn(ctx, json.dumps(template_v1))
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))
    ctx.on_cleanup(lambda: _stop_crawler_if_running(ctx, crawler_name))

    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    sqs = ctx.client("sqs")
    queue1_url = stack["outputs"]["Queue1Url"]
    queue2_url = stack["outputs"]["Queue2Url"]

    # First (full-listing) crawl establishes event mode.
    s3.put_object(Bucket=bucket_name, Key="data/dt=2023-01-01/file1.csv", Body=b"a,b\n1,2\n")
    glue.start_crawler(Name=crawler_name)
    crawler = _wait_for_crawler_ready(ctx, crawler_name)
    assert crawler["LastCrawl"]["Status"] == "SUCCEEDED", crawler["LastCrawl"]

    tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    table_name = tables[0]["Name"]
    partitions = glue.get_partitions(DatabaseName=db_name, TableName=table_name)["Partitions"]
    assert len(partitions) == 1, f"expected 1 partition after the initial full crawl, got {len(partitions)}: {partitions}"

    # Second object still routes to Queue1 (pre-update wiring); consume it before updating.
    s3.put_object(Bucket=bucket_name, Key="data/dt=2023-01-02/file2.csv", Body=b"a,b\n3,4\n")
    _poll_until(
        lambda: _approx_count(sqs, queue1_url),
        lambda n: n >= 1,
        timeout_s=90,
        interval_s=3.0,
        description="pre-update S3 event delivered to Queue1",
    )
    glue.start_crawler(Name=crawler_name)
    crawler = _wait_for_crawler_ready(ctx, crawler_name)
    assert crawler["LastCrawl"]["Status"] == "SUCCEEDED", crawler["LastCrawl"]
    partitions = glue.get_partitions(DatabaseName=db_name, TableName=table_name)["Partitions"]
    assert len(partitions) == 2, f"expected 2 partitions after consuming the pre-update Queue1 event, got {len(partitions)}: {partitions}"
    _poll_until(lambda: _approx_count(sqs, queue1_url), lambda n: n == 0, timeout_s=60, interval_s=3.0, description="Queue1 drained pre-update")

    # Update the stack: bucket notification and crawler EventQueueArn both now point at Queue2.
    template_v2 = _build_template(bucket_name, queue1_name, queue2_name, role_name, db_name, crawler_name, active="Queue2")
    _update_stack_and_wait(ctx, stack["stack_name"], json.dumps(template_v2))

    # A new object should now be delivered ONLY to Queue2.
    s3.put_object(Bucket=bucket_name, Key="data/dt=2023-01-03/file3.csv", Body=b"a,b\n5,6\n")
    _poll_until(
        lambda: _approx_count(sqs, queue2_url),
        lambda n: n >= 1,
        timeout_s=90,
        interval_s=3.0,
        description="post-update S3 event delivered to Queue2",
    )
    assert _approx_count(sqs, queue1_url) == 0, "Queue1 must not receive events after the rewire"

    glue.start_crawler(Name=crawler_name)
    crawler = _wait_for_crawler_ready(ctx, crawler_name)
    assert crawler["LastCrawl"]["Status"] == "SUCCEEDED", crawler["LastCrawl"]
    partitions = glue.get_partitions(DatabaseName=db_name, TableName=table_name)["Partitions"]
    assert len(partitions) == 3, f"expected 3 partitions after consuming the post-update Queue2 event, got {len(partitions)}: {partitions}"

    _poll_until(lambda: _approx_count(sqs, queue2_url), lambda n: n == 0, timeout_s=60, interval_s=3.0, description="Queue2 drained post-update")
    n1 = _approx_count(sqs, queue1_url)
    diag = _peek_queue1_body(sqs, queue1_url) if n1 else ""
    assert n1 == 0, f"Queue1 must stay untouched by the post-update crawl; count={n1} sample={diag!r}"


def _peek_queue1_body(sqs, queue_url: str) -> str:
    resp = sqs.receive_message(QueueUrl=queue_url, MaxNumberOfMessages=1, VisibilityTimeout=0, WaitTimeSeconds=0)
    msgs = resp.get("Messages", [])
    if not msgs:
        return "<no message retrievable>"
    body = json.loads(msgs[0]["Body"])
    rec = body["Records"][0]
    return f"key={rec['s3']['object']['key']} eventTime={rec['eventTime']} eventName={rec['eventName']}"


def _approx_count(sqs, queue_url: str) -> int:
    return int(
        sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"])["Attributes"][
            "ApproximateNumberOfMessages"
        ]
    )


def _build_template(bucket_name, queue1_name, queue2_name, role_name, db_name, crawler_name, *, active: str) -> dict[str, Any]:
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "Queue1": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue1_name}},
            "Queue2": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue2_name}},
            "Queue1Policy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue1"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "s3.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["Queue1", "Arn"]},
                                "Condition": {"ArnLike": {"aws:SourceArn": bucket_arn}},
                            }
                        ],
                    },
                },
            },
            "Queue2Policy": {
                "Type": "AWS::SQS::QueuePolicy",
                "Properties": {
                    "Queues": [{"Ref": "Queue2"}],
                    "PolicyDocument": {
                        "Version": "2012-10-17",
                        "Statement": [
                            {
                                "Effect": "Allow",
                                "Principal": {"Service": "s3.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["Queue2", "Arn"]},
                                "Condition": {"ArnLike": {"aws:SourceArn": bucket_arn}},
                            }
                        ],
                    },
                },
            },
            "DataBucket": {
                "Type": "AWS::S3::Bucket",
                "DependsOn": ["Queue1Policy", "Queue2Policy"],
                "Properties": {
                    "BucketName": bucket_name,
                    "NotificationConfiguration": {
                        "QueueConfigurations": [
                            {"Event": "s3:ObjectCreated:*", "Queue": {"Fn::GetAtt": [active, "Arn"]}}
                        ]
                    },
                },
            },
            "CrawlerRole": {
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
                            "PolicyName": "sqs-and-s3-access",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": [
                                            "sqs:ReceiveMessage",
                                            "sqs:DeleteMessage",
                                            "sqs:GetQueueAttributes",
                                            "sqs:GetQueueUrl",
                                            "sqs:SetQueueAttributes",
                                            "sqs:PurgeQueue",
                                        ],
                                        "Resource": [
                                            {"Fn::GetAtt": ["Queue1", "Arn"]},
                                            {"Fn::GetAtt": ["Queue2", "Arn"]},
                                        ],
                                    },
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:GetObject", "s3:ListBucket"],
                                        "Resource": [bucket_arn, f"{bucket_arn}/*"],
                                    },
                                ],
                            },
                        }
                    ],
                },
            },
            "GlueDatabase": {
                "Type": "AWS::Glue::Database",
                "Properties": {"CatalogId": {"Ref": "AWS::AccountId"}, "DatabaseInput": {"Name": db_name}},
            },
            "Crawler": {
                "Type": "AWS::Glue::Crawler",
                "DependsOn": "GlueDatabase",
                "Properties": {
                    "Name": crawler_name,
                    "Role": {"Fn::GetAtt": ["CrawlerRole", "Arn"]},
                    "DatabaseName": db_name,
                    "Targets": {
                        "S3Targets": [
                            {
                                "Path": f"s3://{bucket_name}/data/",
                                "EventQueueArn": {"Fn::GetAtt": [active, "Arn"]},
                            }
                        ]
                    },
                    "RecrawlPolicy": {"RecrawlBehavior": "CRAWL_EVENT_MODE"},
                    "SchemaChangePolicy": {"UpdateBehavior": "UPDATE_IN_DATABASE", "DeleteBehavior": "LOG"},
                },
            },
        },
        "Outputs": {
            "Queue1Url": {"Value": {"Ref": "Queue1"}},
            "Queue2Url": {"Value": {"Ref": "Queue2"}},
        },
    }


# ===== helpers =====
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
            if exc.response["Error"]["Code"] == "ValidationError" and "does not exist" in str(exc):
                return "GONE"
            raise

    status = _poll_until(
        _status,
        lambda s: s in {"DELETE_COMPLETE", "DELETE_FAILED", "GONE"},
        timeout_s=120,
        interval_s=2.0,
        description=f"delete stack {stack_name}",
    )
    if status == "DELETE_FAILED":
        raise AssertionError(f"delete stack {stack_name} ended in DELETE_FAILED")


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


def _update_stack_and_wait(ctx, stack_name: str, template_body: str, timeout_s: float = 300.0) -> None:
    cfn = ctx.client("cloudformation")
    cfn.update_stack(
        StackName=stack_name,
        TemplateBody=template_body,
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )

    def _status():
        return cfn.describe_stacks(StackName=stack_name)["Stacks"][0]["StackStatus"]

    _poll_until(
        _status,
        lambda s: s in {"UPDATE_COMPLETE", "UPDATE_ROLLBACK_COMPLETE", "UPDATE_FAILED", "UPDATE_ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"update stack {stack_name}",
    )
    status = _status()
    if status != "UPDATE_COMPLETE":
        raise AssertionError(f"Stack update {stack_name} ended in {status}")


def _wait_for_crawler_ready(ctx, crawler_name: str, timeout_s: float = 600.0) -> dict[str, Any]:
    glue = ctx.client("glue")
    return _poll_until(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"],
        lambda c: c["State"] == "READY",
        timeout_s=timeout_s,
        interval_s=10.0,
        description=f"crawler {crawler_name} back to READY",
    )


def _stop_crawler_if_running(ctx, crawler_name: str) -> None:
    glue = ctx.client("glue")
    try:
        state = glue.get_crawler(Name=crawler_name)["Crawler"]["State"]
        if state != "READY":
            glue.stop_crawler(Name=crawler_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFoundException", "CrawlerNotRunningException", "CrawlerStoppingException"):
            raise


def _empty_bucket(ctx, bucket_name: str) -> None:
    s3 = ctx.client("s3")
    try:
        while True:
            resp = s3.list_objects_v2(Bucket=bucket_name)
            contents = resp.get("Contents", [])
            if not contents:
                break
            failed = s3.delete_objects(
                Bucket=bucket_name, Delete={"Objects": [{"Key": o["Key"]} for o in contents]}
            ).get("Errors")
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
