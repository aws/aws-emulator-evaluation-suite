"""concurrent-pipeline-executions-limit-exceeded."""
from __future__ import annotations

import io
import json
import time
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-pipeline-executions-limit-exceeded"
GROUP = "concurrency"
SERVICES = ["codepipeline"]

# CodePipeline's fixed, non-adjustable quota for active executions in a
# PARALLEL execution mode pipeline (AWS General Reference: CodePipeline
# endpoints and quotas -> "Active executions per pipeline": 50, all regions).
_ACTIVE_EXECUTIONS_QUOTA = 50
# A small margin past the quota: enough to observe the rejection, not so much that a
# sequential probe (see below) takes unreasonably long.
_SEARCH_CEILING = _ACTIVE_EXECUTIONS_QUOTA + 5
_LIMIT_MESSAGE = (
    "The limit for concurrent pipeline executions has been exceeded. Please try again later."
)


@tags("axis:rejection", "cap:c3", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Starting more concurrent executions than a PARALLEL-mode pipeline's fixed
    50-active-execution quota allows returns
    ConcurrentPipelineExecutionsLimitExceededException for the overflow."""
    cp = ctx.client("codepipeline")

    # Long enough that every sequentially-submitted execution (see below) is still active when
    # the ceiling is probed, even accounting for throttle-retry delay -- AND long enough that
    # the earliest executions have not DRAINED by the time the 51st is submitted, which is why
    # 120s was not enough (each start is paced 1s apart and the Source stage itself takes tens
    # of seconds, so the first execution could complete its delay before the last was started,
    # freeing a slot and keeping the active count permanently under the ceiling). 840s is inside
    # Lambda's 900s maximum timeout.
    delay_seconds = 840
    lambda_arn = _create_delay_lambda(ctx, delay_seconds)
    role_arn = _create_service_role(
        ctx, extra_statements=[{"Effect": "Allow", "Action": "lambda:InvokeFunction", "Resource": "*"}]
    )
    artifact_bucket = _create_bucket(ctx)
    source_bucket = _create_bucket(ctx, versioned=True)
    source_key = "src/app.zip"
    _put_zip_object(ctx, source_bucket, source_key, "app.txt", b"concurrency-payload")

    name = ctx.unique_name("sim2real-cp-conc-")
    pipeline_decl = {
        "name": name,
        "roleArn": role_arn,
        "artifactStore": {"type": "S3", "location": artifact_bucket},
        "pipelineType": "V2",
        "executionMode": "PARALLEL",
        "stages": [
            _source_stage(source_bucket, source_key),
            _delay_stage(lambda_arn),
        ],
    }
    create_resp = _create_with_role_propagation(
        cp, pipeline_decl, tags=[{"key": "sim2real", "value": CHECK}], timeout_s=90.0
    )
    ctx.on_cleanup(lambda: _delete_pipeline(cp, name))
    assert create_resp["pipeline"].get("executionMode") == "PARALLEL", create_resp["pipeline"]

    # StartPipelineExecution has its own request-rate quota, far tighter than the
    # 50-active-execution ceiling under test here. A concurrent burst of calls
    # saturates that rate limiter long before the active-execution quota is ever
    # reached, so it hits throttling first. Sequential submission, each
    # call retried past transient throttling, is what reliably reaches the real
    # ceiling. A throttled call backs off and retries inside _attempt_start, so the pacing
    # follows the target's own rate limiter and a fast target is never slowed.
    started_ids: list[str] = []
    quota_error = None
    for _ in range(_SEARCH_CEILING):
        outcome = _attempt_start(cp, name)
        if outcome[0] == "ok":
            started_ids.append(outcome[1])
            continue
        assert outcome[1] == "ConcurrentPipelineExecutionsLimitExceededException", (
            "expected only the documented quota-exceeded code once the ceiling is "
            "reached; got a different error before that",
            outcome,
            started_ids,
        )
        assert outcome[2] == _LIMIT_MESSAGE, (outcome[2], _LIMIT_MESSAGE)
        quota_error = outcome[1]
        break

    assert quota_error is not None, (
        f"never observed ConcurrentPipelineExecutionsLimitExceededException within "
        f"{_SEARCH_CEILING} sequential attempts",
        started_ids,
    )
    # positive control: the accepted attempts are real, distinct executions, and
    # there were some -- this is not "everything gets rejected".
    assert len(set(started_ids)) == len(started_ids), ("duplicate execution ids", started_ids)
    assert len(started_ids) >= 1, ("expected at least one accepted execution", started_ids)
    # NOT "exactly 50": CodePipeline auto-triggers an execution the moment a pipeline with an S3
    # source is created. That uncounted execution occupies one of the 50 active slots, so OUR
    # accepted count lands at the ceiling minus however many executions we did not start. Assert the
    # count cannot EXCEED the ceiling -- that is the part the quota actually promises.
    assert len(started_ids) <= _ACTIVE_EXECUTIONS_QUOTA, (
        "more executions were accepted than the documented 50-active-execution ceiling allows",
        len(started_ids),
    )

    # Independent terminal read, through a different operation than the mutating
    # StartPipelineExecution calls: the pipeline's own execution history must show
    # exactly the executions that were reported as started -- no more (the rejected
    # attempt must not have created anything) and no fewer (every accepted attempt
    # must be real, not a phantom success).
    listed_ids = _list_execution_ids(cp, name)
    assert set(started_ids) <= listed_ids, (
        "every StartPipelineExecution reported as accepted must be independently "
        "visible via ListPipelineExecutions",
        set(started_ids) - listed_ids,
    )
    # The rejected StartPipelineExecution must not have created an execution. The pipeline's
    # own auto-triggered execution is the ONE entry that is legitimately not ours, so allow
    # exactly that much slack rather than demanding strict equality.
    assert len(listed_ids) - len(started_ids) <= 1, (
        "ListPipelineExecutions reports more executions than the accepted attempts plus the "
        "pipeline's own auto-triggered execution -- the rejected StartPipelineExecution must "
        "not have created one",
        len(listed_ids),
        len(started_ids),
    )


# ===== helpers =====


def _list_execution_ids(cp, name: str) -> set:
    ids = set()
    for page in cp.get_paginator("list_pipeline_executions").paginate(pipelineName=name):
        ids.update(s["pipelineExecutionId"] for s in page.get("pipelineExecutionSummaries", []))
    return ids


def _attempt_start(cp, name: str, max_attempts: int = 8):
    for attempt in range(max_attempts):
        try:
            resp = cp.start_pipeline_execution(name=name)
            return ("ok", resp["pipelineExecutionId"])
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("ThrottlingException", "TooManyRequestsException", "RequestLimitExceeded"):
                if attempt < max_attempts - 1:
                    time.sleep(2 * (attempt + 1))
                    continue
                return ("error", "ThrottledOut")
            return ("error", code, e.response["Error"].get("Message"))
    return ("error", "ThrottledOut")


def _delete_pipeline(cp, name):
    try:
        cp.delete_pipeline(name=name)
    except ClientError as e:
        if e.response["Error"]["Code"] != "PipelineNotFoundException":
            raise


def _source_stage(source_bucket: str, source_key: str) -> dict:
    return {
        "name": "Source",
        "actions": [
            {
                "name": "Source",
                "actionTypeId": {
                    "category": "Source",
                    "owner": "AWS",
                    "provider": "S3",
                    "version": "1",
                },
                "outputArtifacts": [{"name": "SourceOutput"}],
                "configuration": {
                    "S3Bucket": source_bucket,
                    "S3ObjectKey": source_key,
                    "PollForSourceChanges": "false",
                },
            }
        ],
    }


def _delay_stage(lambda_arn: str) -> dict:
    function_name = lambda_arn.rsplit(":", 1)[-1]
    return {
        "name": "Delay",
        "actions": [
            {
                "name": "Delay",
                "actionTypeId": {
                    "category": "Invoke",
                    "owner": "AWS",
                    "provider": "Lambda",
                    "version": "1",
                },
                "configuration": {"FunctionName": function_name},
            }
        ],
    }


def _zip_bytes(filename: str, content: bytes) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, content)
    return buf.getvalue()


def _put_zip_object(ctx, bucket: str, key: str, filename: str, content: bytes) -> None:
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key=key, Body=_zip_bytes(filename, content))


def _create_bucket(ctx, versioned: bool = False) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-cp-")
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint
    # for; every other region requires one. Region-pinned by the S3 API itself, not a
    # convenience default.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    if versioned:
        s3.put_bucket_versioning(Bucket=bucket, VersioningConfiguration={"Status": "Enabled"})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": CHECK}]})

    def _cleanup():
        try:
            _empty_bucket(ctx, bucket)
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _empty_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    paginator = s3.get_paginator("list_object_versions")
    for page in paginator.paginate(Bucket=bucket):
        objs = [{"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("Versions", [])]
        objs += [
            {"Key": v["Key"], "VersionId": v["VersionId"]} for v in page.get("DeleteMarkers", [])
        ]
        if objs:
            failed = s3.delete_objects(Bucket=bucket, Delete={"Objects": objs}).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")


def _create_service_role(ctx, extra_statements=None) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-cp-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "codepipeline.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]

    def _cleanup_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)

    statements = [{"Effect": "Allow", "Action": ["s3:*"], "Resource": "*"}]
    if extra_statements:
        statements.extend(extra_statements)
    policy = {"Version": "2012-10-17", "Statement": statements}
    iam.put_role_policy(RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(policy))
    return role["Arn"]


def _create_with_role_propagation(cp, declaration, *, tags=None, timeout_s):
    """IAM role/policy propagation is eventually consistent; CreatePipeline can
    transiently report the just-created role as unassumable while it propagates.
    Retry only that specific, bounded transient -- never an unconditional sleep."""
    deadline = time.monotonic() + timeout_s
    kwargs = {"pipeline": declaration}
    if tags is not None:
        kwargs["tags"] = tags
    while True:
        try:
            return cp.create_pipeline(**kwargs)
        except ClientError as exc:
            err = exc.response.get("Error", {})
            transient = (
                err.get("Code") == "InvalidStructureException"
                and "AssumeRole" in err.get("Message", "")
            )
            if not transient or time.monotonic() >= deadline:
                raise
            time.sleep(5)


def _create_delay_lambda(ctx, delay_seconds: int) -> str:
    iam = ctx.client("iam")
    lam = ctx.client("lambda")

    role_name = ctx.unique_name("sim2real-cp-lambdarole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )["Role"]

    def _cleanup_role():
        try:
            iam.delete_role_policy(RoleName=role_name, PolicyName="inline")
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup_role)

    inline_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "*",
            },
            {
                "Effect": "Allow",
                "Action": ["codepipeline:PutJobSuccessResult", "codepipeline:PutJobFailureResult"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="inline", PolicyDocument=json.dumps(inline_policy)
    )

    src = (
        "import time\n"
        "import boto3\n\n"
        f"DELAY_SECONDS = {delay_seconds}\n\n"
        "def handler(event, context):\n"
        "    time.sleep(DELAY_SECONDS)\n"
        "    job_id = event['CodePipeline.job']['id']\n"
        "    boto3.client('codepipeline').put_job_success_result(jobId=job_id)\n"
    )
    code_zip = _zip_bytes("index.py", src.encode("utf-8"))

    function_name = ctx.unique_name("sim2real-cp-delay-")

    def _cleanup_fn():
        try:
            lam.delete_function(FunctionName=function_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup_fn)

    # Give this Lambda enough headroom to survive many concurrent pipeline
    # executions invoking it at once (account default concurrency is 1000).
    last_err = None
    deadline = time.monotonic() + 60.0
    resp = None
    while time.monotonic() < deadline:
        try:
            ctx.on_cleanup(lambda _n=function_name: _delete_lambda_log_group(ctx, _n))
            resp = lam.create_function(
                FunctionName=function_name,
                Runtime="python3.12",
                Role=role["Arn"],
                Handler="index.handler",
                Code={"ZipFile": code_zip},
                Timeout=max(60, delay_seconds + 30),
                Publish=True,
                Tags={"sim2real": CHECK},
            )
            break
        except ClientError as e:
            last_err = e
            if e.response["Error"]["Code"] != "InvalidParameterValueException":
                raise
            time.sleep(3.0)
    if resp is None:
        raise AssertionError(f"lambda create_function never succeeded: {last_err}")

    _poll_until_active(lam, function_name)
    return resp["FunctionArn"]


def _poll_until_active(lam, function_name: str, timeout_s: float = 60.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = lam.get_function_configuration(FunctionName=function_name)["State"]
        if last == "Active":
            return
        time.sleep(2.0)
    raise AssertionError(f"lambda never became Active; last state={last!r}")


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
