"""eventbridge-s3-object-created-triggers-glue-crawler-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-s3-object-created-triggers-glue-crawler-positive"
GROUP = "event-propagation"
SERVICES = ["emr", "glue", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge rule on the S3 'Object Created' event invokes a Lambda target that
    starts a Glue crawler, and the crawler is observed to actually run to completion."""
    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    events = ctx.client("events")

    bucket = ctx.unique_name("sim2real-behav-crawlsrc-")
    _create_bucket(ctx, s3, bucket)
    s3.put_bucket_notification_configuration(
        Bucket=bucket, NotificationConfiguration={"EventBridgeConfiguration": {}}
    )
    s3.put_object(Bucket=bucket, Key="data/seed.csv", Body=b"id,value\n1,10\n2,20\n")

    crawler_role_arn, _ = _create_role(
        ctx,
        "glue.amazonaws.com",
        ["arn:aws:iam::aws:policy/service-role/AWSGlueServiceRole"],
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["s3:GetObject", "s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                }
            ],
        },
    )

    db_name = ctx.unique_name("sim2real_behav_db_").replace("-", "_")
    glue.create_database(DatabaseInput={"Name": db_name})
    ctx.on_cleanup(lambda: glue.delete_database(Name=db_name))

    crawler_name = ctx.unique_name("sim2real-behav-crawler-")
    _call_with_role_retry(
        lambda: glue.create_crawler(
            Name=crawler_name,
            Role=crawler_role_arn,
            DatabaseName=db_name,
            Targets={"S3Targets": [{"Path": f"s3://{bucket}/data/"}]},
        )
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=crawler_name))

    lambda_role_arn, _ = _create_role(
        ctx,
        "lambda.amazonaws.com",
        ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "glue:StartCrawler",
                    "Resource": f"arn:aws:glue:{ctx.region}:*:crawler/{crawler_name}",
                }
            ],
        },
    )
    code = (
        "import boto3, os\n"
        "def handler(event, context):\n"
        "    client = boto3.client('glue')\n"
        "    try:\n"
        "        client.start_crawler(Name=os.environ['CRAWLER_NAME'])\n"
        "    except client.exceptions.CrawlerRunningException:\n"
        "        pass\n"
        "    return {'ok': True}\n"
    )
    fn_name, fn_arn = _create_lambda_function(
        ctx, lambda_role_arn, code, env={"CRAWLER_NAME": crawler_name}
    )

    rule_name = ctx.unique_name("sim2real-behav-rule-")
    pattern = {
        "source": ["aws.s3"],
        "detail-type": ["Object Created"],
        "detail": {"bucket": {"name": [bucket]}},
    }
    rule_arn = events.put_rule(
        Name=rule_name, EventPattern=json.dumps(pattern), State="ENABLED"
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    _allow_eventbridge_to_invoke_lambda(ctx, fn_name, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": fn_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["1"]))

    # trigger the chain: S3 Object Created -> EventBridge rule -> Lambda -> glue.StartCrawler
    s3.put_object(Bucket=bucket, Key="data/trigger.csv", Body=b"id,value\n3,30\n")

    final = _poll_until(
        lambda: glue.get_crawler(Name=crawler_name)["Crawler"],
        lambda c: c["State"] == "READY" and "LastCrawl" in c,
        timeout_s=240,
        interval_s=5,
        description="crawler started indirectly by the Lambda target and run to completion",
    )
    assert final["LastCrawl"]["Status"] == "SUCCEEDED", (
        "expected the crawler started indirectly by the EventBridge->Lambda target to finish its "
        f"LastCrawl as SUCCEEDED, got {final['LastCrawl']['Status']!r} "
        f"(ErrorMessage={final['LastCrawl'].get('ErrorMessage')!r})"
    )


def _poll_until(
    probe, predicate, *, timeout_s=60.0, interval_s=1.0, description="condition"
):
    """Poll probe() until predicate(result) is truthy; return the final result (raises on timeout)."""
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


def _create_bucket(ctx, s3, bucket: str) -> None:
    kwargs: dict[str, Any] = {}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(Bucket=bucket, **kwargs)

    def _cleanup():
        resp = s3.list_objects_v2(Bucket=bucket)
        keys = [{"Key": o["Key"]} for o in resp.get("Contents", [])]
        if keys:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": keys}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)


def _create_role(
    ctx, trust_service: str, managed_policy_arns: list[str], inline_policy=None, policy_name="inline-policy"
):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": trust_service}, "Action": "sts:AssumeRole"}
        ],
    }
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))[
        "Role"
    ]["Arn"]

    def _cleanup_role():
        for arn in managed_policy_arns:
            try:
                iam.detach_role_policy(RoleName=role_name, PolicyArn=arn)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        if inline_policy:
            try:
                iam.delete_role_policy(RoleName=role_name, PolicyName=policy_name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "NoSuchEntity":
                    raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup_role)

    for arn in managed_policy_arns:
        iam.attach_role_policy(RoleName=role_name, PolicyArn=arn)
    if inline_policy:
        iam.put_role_policy(
            RoleName=role_name, PolicyName=policy_name, PolicyDocument=json.dumps(inline_policy)
        )

    _poll_until(
        lambda: iam.get_role(RoleName=role_name)["Role"]["RoleName"],
        lambda n: n == role_name,
        timeout_s=30,
        interval_s=2,
        description="role visible via get_role",
    )
    return role_arn, role_name


def _call_with_role_retry(fn, timeout_s=120.0, interval_s=5.0):
    """IAM roles are eventually consistent; retry a create-with-role call while it is being
    rejected as not-yet-assumable, rather than sleeping a fixed guess."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            last_exc = e
            code = e.response.get("Error", {}).get("Code", "")
            msg = str(e.response.get("Error", {}).get("Message", ""))
            if code in (
                "AccessDeniedException",
                "AccessDenied",
                "InvalidInputException",
                "InvalidInput",
            ) or (
                code == "InvalidParameterValueException"
                and "cannot be assumed" in msg
            ):
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _make_zip(code: str) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("index.py", code)
    return buf.getvalue()


def _create_lambda_function(ctx, role_arn: str, code: str, env=None, timeout=30):
    lam = ctx.client("lambda")
    name = ctx.unique_name("sim2real-behav-fn-")
    zip_bytes = _make_zip(code)

    def _do_create():
        ctx.on_cleanup(lambda _n=name: _delete_lambda_log_group(ctx, _n))
        return lam.create_function(
            FunctionName=name,
            Runtime="python3.12",
            Role=role_arn,
            Handler="index.handler",
            Code={"ZipFile": zip_bytes},
            Timeout=timeout,
            Environment={"Variables": env or {}},
        )

    resp = _call_with_role_retry(_do_create)
    arn = resp["FunctionArn"]
    ctx.on_cleanup(lambda: lam.delete_function(FunctionName=name))
    _poll_until(
        lambda: lam.get_function(FunctionName=name)["Configuration"]["State"],
        lambda s: s == "Active",
        timeout_s=60,
        interval_s=3,
        description="lambda function Active",
    )
    return name, arn


def _allow_eventbridge_to_invoke_lambda(ctx, function_name: str, rule_arn: str) -> None:
    lam = ctx.client("lambda")
    lam.add_permission(
        FunctionName=function_name,
        StatementId="AllowEventBridgeInvoke",
        Action="lambda:InvokeFunction",
        Principal="events.amazonaws.com",
        SourceArn=rule_arn,
    )


def _delete_lambda_log_group(ctx, function_name: str) -> None:
    """Delete the log group Lambda creates on a function's first log line; one never created is fine."""
    try:
        ctx.client("logs").delete_log_group(logGroupName=f"/aws/lambda/{function_name}")
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
