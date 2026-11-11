"""deploy-glue-crawler-sqs-dlq-configured-positive."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "deploy-glue-crawler-sqs-dlq-configured-positive"
GROUP = "deployment-order"
SERVICES = ["glue", "sqs"]


@tags(
    "axis:happy-path",
    "cap:c2",
    "cap:c4",
    "concern:data-plane",
    "concern:deploy",
    "concern:e2e",
    "concern:eventing",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """A CloudFormation-deployed crawler with a DlqEventQueueArn drains an event message it cannot
    parse off its event queue without failing the crawl, and discards it rather than routing it to
    the DLQ: it deletes it on the first receive, so the message never exhausts a receive count."""
    bucket_name = _xname(ctx, "bkt")
    queue_name = _xname(ctx, "evq")
    dlq_name = _xname(ctx, "dlq")
    role_name = _xname(ctx, "role")
    db_name = _xname(ctx, "db").replace("-", "_")
    crawler_name = _xname(ctx, "crawler")

    template = _build_template(
        bucket_name, queue_name, dlq_name, role_name, db_name, crawler_name
    )
    stack = _deploy_cfn(ctx, json.dumps(template))
    ctx.on_cleanup(lambda: _empty_bucket(ctx, bucket_name))
    ctx.on_cleanup(lambda: _stop_crawler_if_running(ctx, crawler_name))

    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    sqs = ctx.client("sqs")
    queue_url = stack["outputs"]["QueueUrl"]
    dlq_url = stack["outputs"]["DlqUrl"]

    s3.put_object(
        Bucket=bucket_name, Key="data/dt=2023-01-01/file1.csv", Body=b"a,b\n1,2\n"
    )

    crawler = _first_crawl(ctx, crawler_name)
    assert crawler["LastCrawl"]["Status"] == "SUCCEEDED", crawler["LastCrawl"]

    # A message that is not a valid S3 event-notification payload; the crawler cannot parse it.
    malformed_body = json.dumps(
        {"not_an_s3_event": True, "marker": "sim2real-malformed-probe"}
    )
    sqs.send_message(QueueUrl=queue_url, MessageBody=malformed_body)

    _poll_until(
        lambda: int(
            sqs.get_queue_attributes(
                QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
            )["Attributes"]["ApproximateNumberOfMessages"]
        ),
        lambda n: n >= 1,
        timeout_s=30,
        interval_s=2.0,
        description="malformed message visible on main queue before crawl",
    )

    glue.start_crawler(Name=crawler_name)
    crawler = _wait_for_crawler_ready(ctx, crawler_name)
    assert crawler["LastCrawl"]["Status"] == "SUCCEEDED", crawler["LastCrawl"]

    _poll_until(
        lambda: int(
            sqs.get_queue_attributes(
                QueueUrl=queue_url, AttributeNames=["ApproximateNumberOfMessages"]
            )["Attributes"]["ApproximateNumberOfMessages"]
        ),
        lambda n: n == 0,
        timeout_s=60,
        interval_s=3.0,
        description="main queue drained of the malformed event by the crawl",
    )

    # An absence, so watch the DLQ for a bounded window rather than one receive.
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        dlq_messages = sqs.receive_message(
            QueueUrl=dlq_url, MaxNumberOfMessages=10, WaitTimeSeconds=20
        ).get("Messages", [])
        assert not any(malformed_body in m["Body"] for m in dlq_messages), (
            f"the crawler discards an unparseable event; it must not reach the DLQ: {dlq_messages}"
        )


def _build_template(
    bucket_name, queue_name, dlq_name, role_name, db_name, crawler_name
) -> dict[str, Any]:
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "EventQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {
                    "QueueName": queue_name,
                    "VisibilityTimeout": 5,
                    "RedrivePolicy": {
                        "deadLetterTargetArn": {"Fn::GetAtt": ["DlqQueue", "Arn"]},
                        "maxReceiveCount": 1,
                    },
                },
            },
            "DlqQueue": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": dlq_name},
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
                                "Principal": {"Service": "s3.amazonaws.com"},
                                "Action": "sqs:SendMessage",
                                "Resource": {"Fn::GetAtt": ["EventQueue", "Arn"]},
                                "Condition": {"ArnLike": {"aws:SourceArn": bucket_arn}},
                            }
                        ],
                    },
                },
            },
            "DataBucket": {
                "Type": "AWS::S3::Bucket",
                "DependsOn": "EventQueuePolicy",
                "Properties": {
                    "BucketName": bucket_name,
                    "NotificationConfiguration": {
                        "QueueConfigurations": [
                            {
                                "Event": "s3:ObjectCreated:*",
                                "Queue": {"Fn::GetAtt": ["EventQueue", "Arn"]},
                            }
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
                    "ManagedPolicyArns": [
                        "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
                    ],
                    "Policies": [
                        {
                            "PolicyName": "sqs-and-s3-access",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        # The managed AWSGlueServiceRole policy does not cover SQS at all;
                                        # a crawler in CRAWL_EVENT_MODE needs this full action set on BOTH
                                        # the event queue and the DLQ, confirmed against real AWS (a
                                        # narrower per-queue split 403s with sqs:purgequeue then
                                        # sqs:getqueueattributes denied on the DLQ specifically) --
                                        # https://docs.aws.amazon.com/glue/latest/dg/crawler-s3-event-notifications.html
                                        "Effect": "Allow",
                                        "Action": [
                                            "sqs:ReceiveMessage",
                                            "sqs:DeleteMessage",
                                            "sqs:GetQueueAttributes",
                                            "sqs:GetQueueUrl",
                                            "sqs:ListQueueTags",
                                            "sqs:ListDeadLetterSourceQueues",
                                            "sqs:SendMessage",
                                            "sqs:SetQueueAttributes",
                                            "sqs:PurgeQueue",
                                        ],
                                        "Resource": [
                                            {"Fn::GetAtt": ["EventQueue", "Arn"]},
                                            {"Fn::GetAtt": ["DlqQueue", "Arn"]},
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
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseInput": {"Name": db_name},
                },
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
                                "EventQueueArn": {"Fn::GetAtt": ["EventQueue", "Arn"]},
                                "DlqEventQueueArn": {"Fn::GetAtt": ["DlqQueue", "Arn"]},
                            }
                        ]
                    },
                    "RecrawlPolicy": {"RecrawlBehavior": "CRAWL_EVENT_MODE"},
                    "SchemaChangePolicy": {
                        "UpdateBehavior": "UPDATE_IN_DATABASE",
                        "DeleteBehavior": "LOG",
                    },
                },
            },
        },
        "Outputs": {
            "QueueUrl": {"Value": {"Ref": "EventQueue"}},
            "DlqUrl": {"Value": {"Ref": "DlqQueue"}},
        },
    }


# ===== helpers =====
_XSVC_PREFIX = "sim2real-xsvc-"
_MANAGED_TAG_KEY = "sim2real:managed"


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"{description} not met within {timeout_s}s. Last result: {last!r}"
    )


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
        lambda s: s in {"DELETE_COMPLETE", "GONE", "DELETE_FAILED"},
        timeout_s=600,
        interval_s=5.0,
        description=f"delete stack {stack_name}",
    )
    if _status() == "DELETE_FAILED":
        raise AssertionError(f"stack {stack_name} DELETE_FAILED")


def _deploy_cfn(
    ctx,
    template,
    *,
    stack_name=None,
    parameters=None,
    capabilities=None,
    timeout_s=300.0,
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
        lambda s: (
            s
            in {
                "CREATE_COMPLETE",
                "CREATE_FAILED",
                "ROLLBACK_COMPLETE",
                "ROLLBACK_FAILED",
            }
        ),
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name}",
    )
    stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
    if stack["StackStatus"] != "CREATE_COMPLETE":
        raise AssertionError(f"Stack {name} ended in {stack['StackStatus']}")
    outputs = {o["OutputKey"]: o["OutputValue"] for o in stack.get("Outputs", [])}
    return {"stack_name": name, "stack_id": stack_id, "outputs": outputs}


def _wait_for_crawler_ready(
    ctx, crawler_name: str, timeout_s: float = 600.0
) -> dict[str, Any]:
    glue = ctx.client("glue")
    return _poll_until(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"],
        lambda c: c["State"] == "READY",
        timeout_s=timeout_s,
        interval_s=10.0,
        description=f"crawler {crawler_name} back to READY",
    )


def _first_crawl(ctx, crawler_name: str, propagation_s: float = 300.0) -> dict[str, Any]:
    """The first crawl after the stack creates the role's inline SQS policy can run before IAM
    propagates it and fail "not authorized"; rerun it to a deadline until the policy is visible."""
    glue = ctx.client("glue")
    deadline = time.monotonic() + propagation_s
    left = ctx.time_left()
    if left is not None:
        deadline = min(deadline, time.monotonic() + left)
    while True:
        glue.start_crawler(Name=crawler_name)
        crawler = _wait_for_crawler_ready(ctx, crawler_name)
        last = crawler["LastCrawl"]
        if last["Status"] == "SUCCEEDED" or "not authorized" not in last.get("ErrorMessage", ""):
            return crawler
        if time.monotonic() >= deadline:
            return crawler
        time.sleep(2)


def _stop_crawler_if_running(ctx, crawler_name: str) -> None:
    glue = ctx.client("glue")
    try:
        state = glue.get_crawler(Name=crawler_name)["Crawler"]["State"]
        if state != "READY":
            glue.stop_crawler(Name=crawler_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("EntityNotFoundException", "CrawlerNotRunningException"):
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
                Bucket=bucket_name,
                Delete={"Objects": [{"Key": o["Key"]} for o in contents]},
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
