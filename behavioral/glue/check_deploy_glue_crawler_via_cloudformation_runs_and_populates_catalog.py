"""deploy-glue-crawler-via-cloudformation-runs-and-populates-catalog."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deploy-glue-crawler-via-cloudformation-runs-and-populates-catalog"
GROUP = "deploy"
SERVICES = ["glue"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:deploy", "dp:api", "plane:data")
def run(ctx) -> None:
    """A crawler deployed via AWS::Glue::Crawler, once started, actually crawls its S3
    target and populates a new table in the catalog -- verified via GetTables, not just
    that StartCrawler returned 200 and GetCrawler eventually says READY."""
    glue = ctx.client("glue")
    s3 = ctx.client("s3")

    bucket = _create_bucket(ctx)
    key = "data/sample.csv"
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=b"id,name,value\n1,alpha,10\n2,beta,20\n3,gamma,30\n",
    )
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))

    role_arn = _create_glue_role(ctx)

    db_name = ctx.unique_name("sim2real-behav-crawldb-")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    crawler_name = ctx.unique_name("sim2real-behav-crawler-")
    stack_name = ctx.unique_name("sim2real-behav-crawlstack-")
    template = json.dumps(
        {
            "AWSTemplateFormatVersion": "2010-09-09",
            "Resources": {
                "MyCrawler": {
                    "Type": "AWS::Glue::Crawler",
                    "Properties": {
                        "Name": crawler_name,
                        "Role": role_arn,
                        "DatabaseName": db_name,
                        "Targets": {"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
                    },
                }
            },
        }
    )
    ctx.on_cleanup(lambda: _delete_stack(ctx, stack_name))
    _create_stack_with_retry(ctx, stack_name, template)

    # Deployed crawler must exist via the control plane too.
    described = glue.get_crawler(Name=crawler_name)
    assert described["Crawler"]["Name"] == crawler_name

    _start_crawler_with_retry(ctx, crawler_name)
    ctx.on_cleanup(lambda: _cleanup_crawled_tables(ctx, db_name))

    _poll_until(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"]["State"],
        lambda state: state == "READY",
        timeout_s=600.0,
        interval_s=10.0,
    )

    final = glue.get_crawler(Name=crawler_name)
    last_crawl = final["Crawler"].get("LastCrawl", {})
    assert last_crawl.get("Status") == "SUCCEEDED", f"crawl did not succeed: {last_crawl}"

    tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    assert len(tables) >= 1, "crawler did not populate any tables in the catalog"
    locations = [t["StorageDescriptor"]["Location"] for t in tables]
    assert any(loc.startswith(f"s3://{bucket}/") for loc in locations), (
        f"no crawled table points at our S3 target: {locations}"
    )


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-behav-crawl-").lower().replace("_", "-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    return bucket


def _create_glue_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-gluerole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "glue.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(
            RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"
        )
    )
    iam.attach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonS3FullAccess")
    )
    return role_arn


def _start_crawler_with_retry(ctx, crawler_name, timeout_s=60.0):
    glue = ctx.client("glue")
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            glue.start_crawler(Name=crawler_name)
            return
        except Exception as exc:  # role/IAM propagation delay
            last_exc = exc
            time.sleep(5)
    raise AssertionError(f"could not start crawler after retries: {last_exc}")


def _cleanup_crawled_tables(ctx, db_name):
    glue = ctx.client("glue")
    try:
        tables = glue.get_tables(DatabaseName=db_name)["TableList"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise
        return
    for t in tables:
        try:
            glue.delete_table(DatabaseName=db_name, Name=t["Name"])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "EntityNotFoundException":
                raise


def _poll_until(probe, predicate, *, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value={last!r})")


def _wait_for_stack_status(ctx, stack_name, terminal_statuses, timeout_s=180.0):
    """Poll DescribeStacks until the stack reaches one of terminal_statuses; return it."""
    cfn = ctx.client("cloudformation")
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        resp = cfn.describe_stacks(StackName=stack_name)
        stacks = resp.get("Stacks", [])
        if not stacks:
            time.sleep(2)
            continue
        last_status = stacks[0]["StackStatus"]
        if last_status in terminal_statuses:
            return last_status
        time.sleep(3)
    raise AssertionError(f"stack {stack_name} did not reach {terminal_statuses} in {timeout_s}s (last={last_status})")


def _crawler_failure_reasons(ctx, stack_name):
    """ResourceStatusReason of every CREATE_FAILED event of the stack's resources."""
    cfn = ctx.client("cloudformation")
    events = cfn.describe_stack_events(StackName=stack_name).get("StackEvents", [])
    return [
        e.get("ResourceStatusReason", "")
        for e in events
        if e.get("ResourceStatus") == "CREATE_FAILED" and e.get("LogicalResourceId") != stack_name
    ]


def _create_stack_with_retry(ctx, stack_name, template, timeout_s=240.0):
    """CloudFormation's AWS::Glue::Crawler handler validates the role is assumable
    synchronously at stack-create time. IAM role/policy attachment is eventually
    consistent with no API to poll for propagation, so the first attempt can roll
    back on a role that is correct but not yet visible everywhere. Only a rollback
    whose resource failure names the role is retried, bounded by an overall deadline;
    any other rollback fails the check with its reason."""
    deadline = time.monotonic() + timeout_s
    attempt = 0
    reasons: list[str] = []
    while time.monotonic() < deadline:
        attempt += 1
        ctx.client("cloudformation").create_stack(StackName=stack_name, TemplateBody=template)
        status = _wait_for_stack_status(
            ctx, stack_name, {"CREATE_COMPLETE", "CREATE_FAILED", "ROLLBACK_COMPLETE", "ROLLBACK_FAILED"}, timeout_s=90.0
        )
        if status == "CREATE_COMPLETE":
            return
        reasons = _crawler_failure_reasons(ctx, stack_name)
        _delete_stack(ctx, stack_name)
        if not any("role" in r.lower() for r in reasons):
            raise AssertionError(f"stack {stack_name} reached {status}: {reasons}")
        time.sleep(5)
    raise AssertionError(f"stack {stack_name} did not reach CREATE_COMPLETE after {attempt} attempt(s): {reasons}")


def _delete_stack(ctx, stack_name):
    cfn = ctx.client("cloudformation")
    cfn.delete_stack(StackName=stack_name)
    deadline = time.monotonic() + 180.0
    last_status = None
    while time.monotonic() < deadline:
        try:
            resp = cfn.describe_stacks(StackName=stack_name)
        except ClientError as exc:
            if "does not exist" in str(exc):
                return
            raise
        stacks = resp.get("Stacks", [])
        if not stacks:
            return
        last_status = stacks[0]["StackStatus"]
        if last_status == "DELETE_COMPLETE":
            return
        if last_status == "DELETE_FAILED":
            raise AssertionError(f"stack {stack_name} failed to delete: DELETE_FAILED")
        time.sleep(3)
    raise AssertionError(f"stack {stack_name} did not reach DELETE_COMPLETE within 180s (last={last_status})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
