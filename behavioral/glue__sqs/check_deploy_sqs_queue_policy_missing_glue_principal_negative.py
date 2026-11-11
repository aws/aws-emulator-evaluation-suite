"""deploy-sqs-queue-policy-missing-glue-principal-negative."""
from __future__ import annotations

import json
import time
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-sqs-queue-policy-missing-glue-principal-negative"
GROUP = "overly-permissive"
SERVICES = ["glue", "sqs"]


@tags("axis:rejection", "cap:c7", "concern:deploy", "concern:e2e", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """An event-mode AWS::Glue::Crawler whose role lacks SQS consume permissions fails at create
    (InvalidRequest naming SQS:ReceiveMessage, stack rolled back, no crawler); with
    sqs:ReceiveMessage/DeleteMessage it is created with that queue.
    """
    bucket_name = _xname(ctx, "bkt")
    queue_name = _xname(ctx, "evq")
    role_name = _xname(ctx, "role")
    db_name = _xname(ctx, "db").replace("-", "_")
    crawler_name = _xname(ctx, "crawler")

    glue = ctx.client("glue")

    # --- Break: deploy with a role missing sqs:ReceiveMessage/DeleteMessage. The role and the
    #     event-mode wiring are otherwise identical to a working deployment.
    broken_template = _build_broken_template(bucket_name, queue_name, role_name, db_name, crawler_name)
    status, reasons = _deploy_cfn_expect_failure(ctx, json.dumps(broken_template))

    assert status in {"ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}, (
        f"expected the stack to roll back once the Crawler resource was refused, got {status}: {reasons}"
    )
    # message varies: the CloudFormation reason embeds a per-request Glue Request ID and RequestToken
    assert "Crawler(CREATE_FAILED)" in reasons, f"expected the Crawler resource to be the one that failed: {reasons}"
    assert "SQS:ReceiveMessage" in reasons, f"expected the rejection to name the missing action: {reasons}"
    assert "HandlerErrorCode: InvalidRequest" in reasons, (
        f"expected Glue's own InvalidRequest for the missing permission, not some other failure: {reasons}"
    )

    # --- Effect absent: the crawler was never created. An independent read, not the deploy's own
    #     response.
    try:
        glue.get_crawler(Name=crawler_name)
        raise AssertionError(f"crawler {crawler_name} must not exist after the stack rolled back")
    except ClientError as exc:
        error = exc.response["Error"]
        assert error["Code"] == "EntityNotFoundException", error
        expected_message = f"Crawler entry with name {crawler_name} does not exist"
        assert error.get("Message") == expected_message, f"expected {expected_message!r}, got {error!r}"

    # --- Restore: the identical role/queue/database/crawler shape, this time with the missing
    #     permission granted. Built directly against the service APIs rather than a second CFN
    #     deploy -- the CFN-specific half of the contract (that CloudFormation itself surfaces the
    #     rejection, not just the underlying Glue API) is already proven above, and a second
    #     multi-minute stack create/rollback cycle would not add evidence, only wall clock.
    iam = ctx.client("iam")
    sqs = ctx.client("sqs")
    s3 = ctx.client("s3")

    role_arn = _create_role(ctx, iam, role_name)
    queue_arn = _create_queue(ctx, sqs, queue_name)
    _put_fixed_role_policy(iam, role_name, queue_arn, bucket_name)
    _create_bucket(ctx, s3, bucket_name, ctx.region)
    _create_database(ctx, glue, db_name)

    _create_crawler_with_retry(
        glue,
        timeout_s=90.0,
        interval_s=5.0,
        Name=crawler_name,
        Role=role_arn,
        DatabaseName=db_name,
        Targets={"S3Targets": [{"Path": f"s3://{bucket_name}/data/", "EventQueueArn": queue_arn}]},
        RecrawlPolicy={"RecrawlBehavior": "CRAWL_EVENT_MODE"},
        SchemaChangePolicy={"UpdateBehavior": "UPDATE_IN_DATABASE", "DeleteBehavior": "LOG"},
        Tags=_xsvc_resource_tags(),
    )
    ctx.on_cleanup(lambda: _delete_crawler_ignore(ctx, crawler_name))

    # --- Identical call now succeeds: an independent read (not CreateCrawler's own response)
    #     confirms the same shape that was rejected above now exists.
    crawler = glue.get_crawler(Name=crawler_name)["Crawler"]
    assert crawler["Role"] in (role_arn, role_name), f"expected the fixed role, got {crawler!r}"
    assert crawler["RecrawlPolicy"]["RecrawlBehavior"] == "CRAWL_EVENT_MODE", crawler
    assert crawler["Targets"]["S3Targets"][0]["EventQueueArn"] == queue_arn, crawler


def _build_broken_template(bucket_name, queue_name, role_name, db_name, crawler_name) -> dict[str, Any]:
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    return {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Resources": {
            "EventQueue": {"Type": "AWS::SQS::Queue", "Properties": {"QueueName": queue_name}},
            "DataBucket": {"Type": "AWS::S3::Bucket", "Properties": {"BucketName": bucket_name}},
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
                            "PolicyName": "s3-access-only",
                            "PolicyDocument": {
                                "Version": "2012-10-17",
                                "Statement": [
                                    {
                                        "Effect": "Allow",
                                        "Action": ["s3:GetObject", "s3:ListBucket"],
                                        "Resource": [bucket_arn, f"{bucket_arn}/*"],
                                    },
                                    {
                                        # Deliberately NOT sqs:ReceiveMessage / sqs:DeleteMessage --
                                        # that is the exact permission this check proves
                                        # CloudFormation refuses to deploy without, at Crawler
                                        # CREATE time (not merely at the crawler's first run).
                                        "Effect": "Allow",
                                        "Action": ["sqs:SetQueueAttributes", "sqs:GetQueueUrl", "sqs:PurgeQueue"],
                                        "Resource": {"Fn::GetAtt": ["EventQueue", "Arn"]},
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
                                "EventQueueArn": {"Fn::GetAtt": ["EventQueue", "Arn"]},
                            }
                        ]
                    },
                    "RecrawlPolicy": {"RecrawlBehavior": "CRAWL_EVENT_MODE"},
                    "SchemaChangePolicy": {"UpdateBehavior": "UPDATE_IN_DATABASE", "DeleteBehavior": "LOG"},
                },
            },
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


def _failed_event_reasons(cfn, stack_name: str) -> str:
    try:
        events = cfn.describe_stack_events(StackName=stack_name)["StackEvents"]
    except ClientError:
        return "<no events>"
    reasons = [
        f"{e['LogicalResourceId']}({e['ResourceStatus']}): {e.get('ResourceStatusReason', '')}"
        for e in events
        if e["ResourceStatus"].endswith("FAILED")
    ]
    return "; ".join(reasons[:10])


def _deploy_cfn_expect_failure(ctx, template: str, *, stack_name=None, timeout_s: float = 280.0) -> tuple[str, str]:
    ctx.verify_account_safety()
    cfn = ctx.client("cloudformation")
    name = stack_name or _xname(ctx, "stk")
    cfn.create_stack(
        StackName=name,
        TemplateBody=template,
        Tags=_xsvc_tags_kv(),
        Capabilities=["CAPABILITY_IAM", "CAPABILITY_NAMED_IAM"],
    )
    ctx.on_cleanup(lambda: _delete_stack_and_wait(ctx, name))
    status = _poll_until(
        lambda: cfn.describe_stacks(StackName=name)["Stacks"][0]["StackStatus"],
        lambda s: s in {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"},
        timeout_s=timeout_s,
        interval_s=5.0,
        description=f"CFN stack {name} to reach a terminal status",
    )
    reasons = _failed_event_reasons(cfn, name)
    return status, reasons


def _create_role(ctx, iam, role_name: str) -> str:
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
                ],
            }
        ),
        Tags=_xsvc_tags_kv(),
    )["Role"]
    ctx.on_cleanup(lambda: _delete_role_ignore(ctx, role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole")
    return role["Arn"]


def _put_fixed_role_policy(iam, role_name: str, queue_arn: str, bucket_name: str) -> None:
    bucket_arn = f"arn:aws:s3:::{bucket_name}"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="sqs-and-s3-access",
        PolicyDocument=json.dumps(
            {
                "Version": "2012-10-17",
                "Statement": [
                    {
                        # CreateCrawler validates more than sqs:ReceiveMessage at create time: a role
                        # with only Receive/Delete/GetQueueAttributes/GetQueueUrl is refused for
                        # missing sqs:SetQueueAttributes too (Glue provisions the queue's redrive
                        # wiring on create), so the role carries the full set.
                        "Effect": "Allow",
                        "Action": [
                            "sqs:ReceiveMessage",
                            "sqs:DeleteMessage",
                            "sqs:GetQueueAttributes",
                            "sqs:GetQueueUrl",
                            "sqs:SetQueueAttributes",
                            "sqs:PurgeQueue",
                        ],
                        "Resource": queue_arn,
                    },
                    {
                        "Effect": "Allow",
                        "Action": ["s3:GetObject", "s3:ListBucket"],
                        "Resource": [bucket_arn, f"{bucket_arn}/*"],
                    },
                ],
            }
        ),
    )


def _create_queue(ctx, sqs, queue_name: str) -> str:
    sqs.create_queue(QueueName=queue_name, tags=_xsvc_resource_tags())
    queue_url = sqs.get_queue_url(QueueName=queue_name)["QueueUrl"]
    ctx.on_cleanup(lambda: _delete_queue_ignore(sqs, queue_url))
    return sqs.get_queue_attributes(QueueUrl=queue_url, AttributeNames=["QueueArn"])["Attributes"]["QueueArn"]


def _create_bucket(ctx, s3, bucket_name: str, region: str) -> None:
    kwargs: dict[str, Any] = {"Bucket": bucket_name}
    if region != "us-east-1":  # S3 CreateBucket rejects a LocationConstraint that names us-east-1 itself
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: _delete_bucket_ignore(s3, bucket_name))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": _xsvc_tags_kv()})


def _create_database(ctx, glue, db_name: str) -> None:
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: _delete_database_ignore(glue, db_name))


def _create_crawler_with_retry(glue, *, timeout_s: float, interval_s: float, **kwargs) -> None:
    deadline = time.monotonic() + timeout_s
    last_exc: Exception | None = None
    while time.monotonic() < deadline:
        try:
            glue.create_crawler(**kwargs)
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(
        f"CreateCrawler with the fixed role never succeeded within {timeout_s}s "
        f"(IAM-to-Glue propagation should resolve well inside that window): {last_exc}"
    )


def _delete_role_ignore(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        for policy_name in iam.list_role_policies(RoleName=role_name).get("PolicyNames", []):
            iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _delete_queue_ignore(sqs, queue_url: str) -> None:
    try:
        sqs.delete_queue(QueueUrl=queue_url)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in (
            "AWS.SimpleQueueService.NonExistentQueue",
            "QueueDoesNotExist",
        ):
            raise


def _delete_bucket_ignore(s3, bucket_name: str) -> None:
    try:
        s3.delete_bucket(Bucket=bucket_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _delete_database_ignore(glue, db_name: str) -> None:
    try:
        glue.delete_database(Name=db_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _delete_crawler_ignore(ctx, crawler_name: str) -> None:
    try:
        ctx.client("glue").delete_crawler(Name=crawler_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
