"""eventbridge-glue-crawler-completion-triggers-downstream-glue-job-positive."""
from __future__ import annotations

import io
import json
import time
import zipfile
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "eventbridge-glue-crawler-completion-triggers-downstream-glue-job-positive"
GROUP = "event-propagation"
SERVICES = ["emr", "glue", "s3"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "concern:e2e", "concern:eventing", "dp:api", "plane:data")
def run(ctx) -> None:
    """An EventBridge rule on 'Glue Crawler State Change' (state=Succeeded) invokes a
    Lambda target that starts a downstream Glue job, observed running to SUCCEEDED."""
    s3 = ctx.client("s3")
    glue = ctx.client("glue")
    events = ctx.client("events")

    bucket = ctx.unique_name("sim2real-behav-chain-")
    _create_bucket(ctx, s3, bucket)
    s3.put_object(Bucket=bucket, Key="data/seed.csv", Body=b"id,value\n1,10\n")
    script_key = "scripts/downstream.py"
    s3.put_object(Bucket=bucket, Key=script_key, Body=b"print('downstream job ok')\n")

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
            Tags={"sim2real": CHECK},
        )
    )
    ctx.on_cleanup(lambda: glue.delete_crawler(Name=crawler_name))

    job_role_arn, _ = _create_role(
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
    job_name = ctx.unique_name("sim2real-behav-djob-")
    _call_with_role_retry(
        lambda: glue.create_job(
            Name=job_name,
            Role=job_role_arn,
            Command={
                "Name": "pythonshell",
                "ScriptLocation": f"s3://{bucket}/{script_key}",
                "PythonVersion": "3.9",
            },
            MaxCapacity=0.0625,
            Timeout=5,
            Tags={"sim2real": CHECK},
        )
    )
    ctx.on_cleanup(lambda: glue.delete_job(JobName=job_name))

    lambda_role_arn, _ = _create_role(
        ctx,
        "lambda.amazonaws.com",
        ["arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"],
        inline_policy={
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "glue:StartJobRun",
                    "Resource": f"arn:aws:glue:{ctx.region}:*:job/{job_name}",
                }
            ],
        },
    )
    code = (
        "import boto3, os\n"
        "def handler(event, context):\n"
        "    client = boto3.client('glue')\n"
        "    client.start_job_run(JobName=os.environ['DOWNSTREAM_JOB_NAME'])\n"
        "    return {'ok': True}\n"
    )
    fn_name, fn_arn = _create_lambda_function(
        ctx, lambda_role_arn, code, env={"DOWNSTREAM_JOB_NAME": job_name}
    )

    rule_name = ctx.unique_name("sim2real-behav-rule-")
    pattern = {
        "source": ["aws.glue"],
        "detail-type": ["Glue Crawler State Change"],
        "detail": {"crawlerName": [crawler_name], "state": ["Succeeded"]},
    }
    rule_arn = events.put_rule(
        Name=rule_name,
        EventPattern=json.dumps(pattern),
        State="ENABLED",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["RuleArn"]
    ctx.on_cleanup(lambda: events.delete_rule(Name=rule_name))

    _allow_eventbridge_to_invoke_lambda(ctx, fn_name, rule_arn)
    events.put_targets(Rule=rule_name, Targets=[{"Id": "1", "Arn": fn_arn}])
    ctx.on_cleanup(lambda: events.remove_targets(Rule=rule_name, Ids=["1"]))

    glue.start_crawler(Name=crawler_name)

    def _latest_run_state():
        runs = glue.get_job_runs(JobName=job_name, MaxResults=5).get("JobRuns", [])
        return runs[0]["JobRunState"] if runs else None

    _poll_until(
        _latest_run_state,
        lambda s: s is not None,
        timeout_s=300,
        interval_s=10,
        description="downstream job run started by the chained crawler-completion trigger",
    )
    final = _poll_until(
        _latest_run_state,
        lambda s: s in ("SUCCEEDED", "FAILED", "ERROR", "TIMEOUT", "STOPPED"),
        timeout_s=240,
        interval_s=10,
        description="downstream job run terminal state",
    )
    assert final == "SUCCEEDED", f"downstream job run ended in {final}"

    crawler_info = glue.get_crawler(Name=crawler_name)["Crawler"]
    last_crawl_status = crawler_info["LastCrawl"]["Status"]
    assert last_crawl_status == "SUCCEEDED", (
        f"expected the triggering crawler's LastCrawl.Status to be SUCCEEDED, got {last_crawl_status!r}"
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
    try:
        s3.put_bucket_tagging(
            Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]}
        )
    except ClientError:
        pass


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
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]["Arn"]

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
            Tags={"sim2real": CHECK},
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
