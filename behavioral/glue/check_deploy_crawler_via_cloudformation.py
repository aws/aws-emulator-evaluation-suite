"""deploy-crawler-via-cloudformation."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-crawler-via-cloudformation"
GROUP = "deploy"
SERVICES = ["glue"]

_STACK_TERMINAL = {
    "CREATE_COMPLETE",
    "CREATE_FAILED",
    "ROLLBACK_COMPLETE",
    "ROLLBACK_FAILED",
    "DELETE_COMPLETE",
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A CloudFormation-deployed AWS::Glue::Crawler, once started, actually crawls
    its S3 target and populates the Data Catalog with a table -- not merely
    CREATE_COMPLETE on the stack."""
    glue = ctx.client("glue")

    bucket = _create_bucket(ctx)
    csv_body = "id,name,value\n1,alpha,10\n2,beta,20\n3,gamma,30\n"
    _put_object(ctx, bucket, "data/sample.csv", csv_body)

    bucket_arn = f"arn:aws:s3:::{bucket}"
    role_arn = _create_glue_role(
        ctx,
        [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:ListBucket"],
                "Resource": [bucket_arn, f"{bucket_arn}/*"],
            }
        ],
    )

    db_name = ctx.unique_name("sim2real_glue_crdb_").replace("-", "_")
    crawler_name = ctx.unique_name("sim2real-glue-crawler-")
    s3_path = f"s3://{bucket}/data/"

    template = {
        "AWSTemplateFormatVersion": "2010-09-09",
        "Parameters": {
            "CrawlerRoleArn": {"Type": "String"},
            "DatabaseName": {"Type": "String"},
            "CrawlerName": {"Type": "String"},
            "S3Path": {"Type": "String"},
        },
        "Resources": {
            "GlueDatabase": {
                "Type": "AWS::Glue::Database",
                "Properties": {
                    "CatalogId": {"Ref": "AWS::AccountId"},
                    "DatabaseInput": {"Name": {"Ref": "DatabaseName"}},
                },
            },
            "GlueCrawler": {
                "Type": "AWS::Glue::Crawler",
                "DependsOn": "GlueDatabase",
                "Properties": {
                    "Name": {"Ref": "CrawlerName"},
                    "Role": {"Ref": "CrawlerRoleArn"},
                    "DatabaseName": {"Ref": "DatabaseName"},
                    "Targets": {"S3Targets": [{"Path": {"Ref": "S3Path"}}]},
                },
            },
        },
    }
    _deploy_stack(
        ctx,
        template,
        {
            "CrawlerRoleArn": role_arn,
            "DatabaseName": db_name,
            "CrawlerName": crawler_name,
            "S3Path": s3_path,
        },
    )

    # The CFN-deployed crawler and database must actually be usable via the Glue API.
    assert glue.get_crawler(Name=crawler_name)["Crawler"]["DatabaseName"] == db_name
    assert glue.get_database(Name=db_name)["Database"]["Name"] == db_name

    # IAM role/policy attachments can take a few seconds to propagate to other
    # services before they are usable for AssumeRole -- see
    # https://docs.aws.amazon.com/IAM/latest/UserGuide/troubleshoot_general.html#troubleshoot_general_eventual-consistency
    # Retry StartCrawler itself on that specific denial rather than sleeping
    # up front and hoping the window was long enough.
    _start_crawler_with_retry(glue, crawler_name)
    crawler = _wait_crawler_finished(glue, crawler_name)
    assert crawler["LastCrawl"]["Status"] == "SUCCEEDED", crawler["LastCrawl"]

    metrics = glue.get_crawler_metrics(CrawlerNameList=[crawler_name])["CrawlerMetricsList"][0]
    assert metrics["TablesCreated"] + metrics["TablesUpdated"] >= 1, metrics

    tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert len(tables) >= 1, "crawler did not populate the catalog with any table"
    locations = [t["StorageDescriptor"]["Location"] for t in tables]
    assert any(loc.startswith(f"s3://{bucket}/") for loc in locations), locations


def _poll_until(probe, predicate, timeout_s=300.0, interval_s=5.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _start_crawler_with_retry(glue, crawler_name: str, timeout_s: float = 60.0, interval_s: float = 5.0) -> None:
    """StartCrawler can be denied for a few seconds after the crawler's role is
    created, while the role has not yet propagated to Glue. Retry the specific
    denial on a bounded deadline instead of sleeping first and hoping."""
    deadline = time.monotonic() + timeout_s
    last_exc: ClientError | None = None
    while time.monotonic() < deadline:
        try:
            glue.start_crawler(Name=crawler_name)
            return
        except ClientError as exc:
            last_exc = exc
            time.sleep(interval_s)
    raise AssertionError(f"could not start crawler {crawler_name} within {timeout_s}s: {last_exc}")


def _create_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-glue-cr-").lower()
    # us-east-1 rejects CreateBucketConfiguration/LocationConstraint outright; every
    # other region requires it. ctx.region still drives where the bucket actually lands.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        for obj in resp.get("Contents", []):
            s3.delete_object(Bucket=bucket, Key=obj["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _put_object(ctx, bucket: str, key: str, body: str) -> None:
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=body.encode("utf-8"))


def _create_glue_role(ctx, statements) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-glue-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    managed_policy = "arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=managed_policy)
    inline_policy_name = f"{role_name}-inline"
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName=inline_policy_name,
        PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": statements}),
    )

    def _cleanup():
        iam.delete_role_policy(RoleName=role_name, PolicyName=inline_policy_name)
        iam.detach_role_policy(RoleName=role_name, PolicyArn=managed_policy)
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _stack_status(cfn, stack_name: str) -> str:
    try:
        resp = cfn.describe_stacks(StackName=stack_name)
        return resp["Stacks"][0]["StackStatus"]
    except ClientError as e:
        if "does not exist" in str(e):
            return "DELETE_COMPLETE"
        raise


def _delete_stack(ctx, stack_name: str) -> None:
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s == "DELETE_COMPLETE",
        timeout_s=400.0,
        interval_s=10.0,
    )


def _deploy_stack(ctx, template: dict, params: dict) -> str:
    cfn = ctx.client("cloudformation")
    stack_name = ctx.unique_name("sim2real-glue-stack-")
    cfn.create_stack(
        StackName=stack_name,
        TemplateBody=json.dumps(template),
        Parameters=[{"ParameterKey": k, "ParameterValue": v} for k, v in params.items()],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    status = _poll_until(
        lambda: _stack_status(cfn, stack_name),
        lambda s: s in _STACK_TERMINAL,
        timeout_s=400.0,
        interval_s=10.0,
    )
    if status != "CREATE_COMPLETE":
        raise AssertionError(f"stack {stack_name} did not reach CREATE_COMPLETE (status={status})")
    return stack_name


def _wait_crawler_finished(glue, name: str, timeout_s: float = 420.0, interval_s: float = 10.0):
    def probe():
        return glue.get_crawler(Name=name)["Crawler"]

    def done(crawler):
        return crawler["State"] == "READY" and crawler.get("LastCrawl") is not None

    return _poll_until(probe, done, timeout_s=timeout_s, interval_s=interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
