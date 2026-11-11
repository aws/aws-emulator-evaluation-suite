"""ai-benchmark-job-create-delete-lifecycle."""
from __future__ import annotations

import io
import json
import tarfile
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ai-benchmark-job-create-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

#: The endpoint serves a stub scikit-learn inference script the check writes itself, so the
#: container loads in seconds with no trained model; only its InService state matters here.
_INFERENCE_SCRIPT = b"""def model_fn(model_dir):
    return "stub"


def input_fn(request_body, request_content_type):
    return request_body


def predict_fn(input_data, model):
    return [len(input_data)]
"""

# Fallback SageMaker scikit-learn framework image URIs, used only if the `sagemaker` Python SDK
# (which carries the authoritative per-region account-id table) is unavailable. These name AWS's
# own fixed, per-region framework ECR registry account IDs -- a published constant, not a value
# this check controls or varies by account.
_SKLEARN_IMAGE_FALLBACK = {
    "us-east-1": "683313688378.dkr.ecr.us-east-1.amazonaws.com/sagemaker-scikit-learn:1.2-1-cpu-py3",
    "us-west-2": "246618743249.dkr.ecr.us-west-2.amazonaws.com/sagemaker-scikit-learn:1.2-1-cpu-py3",
}
#: Fresh jobs tried for one that is read InProgress and then stopped, before failing.
_LIFECYCLE_ATTEMPTS = 3
_ENDPOINT_TIMEOUT_S = 1200.0
_ENDPOINT_DELETE_TIMEOUT_S = 900.0
_PENDING_TIMEOUT_S = 300.0
_JOB_STOP_TIMEOUT_S = 300.0
#: The workload a job runs: a benchmark job reads its benchmark type from `benchmark.type` and
#: fails without one. This is the documented AIPerf workload with an OpenAI-compatible request
#: schema; the job is stopped while InProgress, so the endpoint never has to serve it.
_WORKLOAD_SPEC = {
    "benchmark": {"type": "aiperf"},
    "parameters": {
        "tokenizer": "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
        "concurrency": 1,
        "request_count": 10,
        "streaming": True,
        "prompt_input_tokens_mean": 550,
        "prompt_input_tokens_stddev": 150,
        "output_tokens_mean": 50,
        "output_tokens_stddev": 10,
        "request_rate": 1.0,
        "benchmark_duration": 60,
    },
    "tooling": {"api_standard": "openai", "version": "0.6.0"},
}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An AIBenchmarkJob against an InService endpoint leaves Pending for InProgress and stops to
    Stopped; once deleted, DescribeAIBenchmarkJob and a second delete of the same name fail ResourceNotFound."""
    sm = ctx.client("sagemaker")

    if not hasattr(sm, "create_ai_benchmark_job"):
        raise AssertionError(
            "installed botocore does not expose create_ai_benchmark_job "
            "(SageMaker AI Benchmark Job API not present in this SDK version)"
        )

    role_arn = _create_sagemaker_execution_role(ctx)
    managed_tags = [{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}]

    workload_name = ctx.unique_name("sim2real-aiwc-bench-")
    sm.create_ai_workload_config(
        AIWorkloadConfigName=workload_name,
        AIWorkloadConfigs={"WorkloadSpec": {"Inline": json.dumps(_WORKLOAD_SPEC)}},
        Tags=managed_tags,
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: sm.delete_ai_workload_config(AIWorkloadConfigName=workload_name)))

    bucket, endpoint_identifier = _create_target_endpoint(ctx, sm, role_arn, managed_tags)

    # A job can end on its own (Failed) before the first read or before the stop lands; such a job
    # never showed the InProgress -> Stopped path, so it is deleted and a fresh one created, up to
    # the attempt cap.
    seen = []
    for _ in range(_LIFECYCLE_ATTEMPTS):
        job_name = ctx.unique_name("sim2real-aibench-")

        def _create(job_name=job_name) -> dict:
            return sm.create_ai_benchmark_job(
                AIBenchmarkJobName=job_name,
                AIWorkloadConfigIdentifier=workload_name,
                BenchmarkTarget={"Endpoint": {"Identifier": endpoint_identifier}},
                OutputConfig={"S3OutputLocation": f"s3://{bucket}/output/{job_name}/"},
                RoleArn=role_arn,
                Tags=managed_tags,
            )

        resp = _retry_role_not_yet_assumable(_create, timeout_s=90.0)
        arn = resp["AIBenchmarkJobArn"]
        cleaned = {"done": False}

        def _cleanup(job_name=job_name, cleaned=cleaned) -> None:
            if not cleaned["done"]:
                _stop_and_delete_job(sm, job_name)

        ctx.on_cleanup(_cleanup)

        desc = sm.describe_ai_benchmark_job(AIBenchmarkJobName=job_name)
        assert desc["AIBenchmarkJobArn"] == arn, (
            f"expected DescribeAIBenchmarkJob to echo the ARN {arn!r} minted by Create, got {desc.get('AIBenchmarkJobArn')!r}"
        )
        # A new job reads Pending until it starts; the lifecycle under test begins once it leaves Pending.
        if desc["AIBenchmarkJobStatus"] == "Pending":
            desc = _poll_until(
                lambda job_name=job_name: sm.describe_ai_benchmark_job(AIBenchmarkJobName=job_name),
                lambda d: d["AIBenchmarkJobStatus"] != "Pending",
                timeout_s=_budget_s(ctx, _PENDING_TIMEOUT_S),
                interval_s=3.0,
            )
        status = desc["AIBenchmarkJobStatus"]
        if status == "InProgress":
            stop_error = None
            try:
                sm.stop_ai_benchmark_job(AIBenchmarkJobName=job_name)
            except ClientError as exc:
                stop_error = exc
            settled = _poll_until(
                lambda job_name=job_name: sm.describe_ai_benchmark_job(AIBenchmarkJobName=job_name)["AIBenchmarkJobStatus"],
                lambda st: st in ("Stopped", "Completed", "Failed"),
                timeout_s=_budget_s(ctx, _JOB_STOP_TIMEOUT_S),
                interval_s=3.0,
            )
            if stop_error is None:
                assert settled == "Stopped", f"expected the stopped job to settle in Stopped, got {settled!r}"
                break
            if settled != "Failed":
                raise stop_error
            seen.append(("InProgress", f"stop refused ({stop_error.response['Error']['Code']}), job {settled}"))
        elif status == "Failed":
            seen.append((status, desc.get("FailureReason")))
        else:
            raise AssertionError(
                f"expected a new AIBenchmarkJob against an InService endpoint to leave Pending for "
                f"InProgress, got {status!r}"
            )
        sm.delete_ai_benchmark_job(AIBenchmarkJobName=job_name)
        cleaned["done"] = True
    else:
        raise AssertionError(
            f"every new job ended Failed before it could be stopped, so none showed the InProgress -> "
            f"Stopped path; (first status, outcome) per job: {seen}"
        )

    sm.delete_ai_benchmark_job(AIBenchmarkJobName=job_name)
    cleaned["done"] = True

    describe_code = _error_code(lambda: sm.describe_ai_benchmark_job(AIBenchmarkJobName=job_name))
    assert describe_code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {describe_code!r}"

    delete_code = _error_code(lambda: sm.delete_ai_benchmark_job(AIBenchmarkJobName=job_name))
    assert delete_code == "ResourceNotFound", f"expected ResourceNotFound on repeat delete, got {delete_code!r}"


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey", "ResourceNotFound"):
            raise


def _stop_and_delete_job(sm, job_name: str) -> None:
    """Teardown: a job deletes only once Completed, Failed or Stopped, so stop it, wait for it to
    settle, then delete it; a job that is already gone is fine."""
    try:
        status = sm.describe_ai_benchmark_job(AIBenchmarkJobName=job_name)["AIBenchmarkJobStatus"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFound":
            return
        raise
    if status not in ("Completed", "Failed", "Stopped", "Stopping"):
        sm.stop_ai_benchmark_job(AIBenchmarkJobName=job_name)
    _poll_until(
        lambda: sm.describe_ai_benchmark_job(AIBenchmarkJobName=job_name)["AIBenchmarkJobStatus"],
        lambda st: st in ("Completed", "Failed", "Stopped"),
        timeout_s=_JOB_STOP_TIMEOUT_S,
        interval_s=5.0,
    )
    _safe_call(lambda: sm.delete_ai_benchmark_job(AIBenchmarkJobName=job_name))


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"]
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _retry_role_not_yet_assumable(fn, timeout_s=90.0, interval_s=3.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            message = e.response["Error"].get("Message", "")
            if code != "ValidationException" or "role" not in message.lower() or time.monotonic() >= deadline:
                raise
            time.sleep(interval_s)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _resolve_sklearn_image_uri(ctx) -> str | None:
    try:
        from sagemaker import image_uris

        return image_uris.retrieve(
            framework="sklearn", region=ctx.region, version="1.2-1", py_version="py3", instance_type="ml.m5.large"
        )
    except Exception:
        pass
    return _SKLEARN_IMAGE_FALLBACK.get(ctx.region)


def _tar_gz(members: dict) -> bytes:
    """A gzipped tar holding *members* (archive name -> bytes)."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def _stage_stub_model(s3, bucket: str) -> tuple[str, str]:
    """Upload the stub model archive and its inference-script source archive; return both URIs."""
    s3.put_object(Bucket=bucket, Key="model/model.tar.gz", Body=_tar_gz({"stub.txt": b"stub\n"}))
    s3.put_object(Bucket=bucket, Key="code/sourcedir.tar.gz", Body=_tar_gz({"inference.py": _INFERENCE_SCRIPT}))
    return f"s3://{bucket}/model/model.tar.gz", f"s3://{bucket}/code/sourcedir.tar.gz"


def _delete_endpoint_when_settled(sm, endpoint_name: str) -> None:
    """DeleteEndpoint once the endpoint has left Creating/Updating (it refuses an in-progress
    endpoint), then wait for it to be gone; an endpoint that is already gone is fine."""
    deadline = time.monotonic() + _ENDPOINT_DELETE_TIMEOUT_S
    while True:
        try:
            status = sm.describe_endpoint(EndpointName=endpoint_name)["EndpointStatus"]
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "ValidationException" and "Could not find endpoint" in err.get("Message", ""):
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(f"endpoint {endpoint_name!r} still {status} at the teardown deadline")
        if status not in ("Creating", "Updating", "SystemUpdating", "RollingBack", "Deleting"):
            sm.delete_endpoint(EndpointName=endpoint_name)
        time.sleep(15.0)


def _create_target_endpoint(ctx, sm, role_arn: str, managed_tags: list) -> tuple[str, str]:
    """An InService endpoint serving the stub model, and the bucket holding its artifacts."""
    image_uri = _resolve_sklearn_image_uri(ctx)
    if image_uri is None:
        raise AssertionError(
            f"no known scikit-learn framework image URI for region {ctx.region} "
            "(sagemaker Python SDK not installed and region absent from the fallback "
            "table); install the sagemaker SDK or extend the fallback map to close this gap"
        )

    s3 = ctx.client("s3")
    # AmazonSageMakerFullAccess scopes its S3 grant to bucket names containing "sagemaker";
    # a bucket without that substring is created but unreadable by the execution role.
    bucket = ctx.unique_name("sim2real-sagemaker-aibench-").lower().replace("_", "-")
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup_bucket() -> None:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                _safe_call(lambda k=obj["Key"]: s3.delete_object(Bucket=bucket, Key=k))
        _safe_call(lambda: s3.delete_bucket(Bucket=bucket))

    ctx.on_cleanup(_cleanup_bucket)
    model_data_url, source_url = _stage_stub_model(s3, bucket)

    model_name = ctx.unique_name("sim2real-aibench-model-")
    _retry_role_not_yet_assumable(
        lambda: sm.create_model(
            ModelName=model_name,
            ExecutionRoleArn=role_arn,
            PrimaryContainer={
                "Image": image_uri,
                "ModelDataUrl": model_data_url,
                "Environment": {
                    "SAGEMAKER_PROGRAM": "inference.py",
                    "SAGEMAKER_SUBMIT_DIRECTORY": source_url,
                    "SAGEMAKER_REGION": ctx.region,
                },
            },
            Tags=managed_tags,
        ),
        timeout_s=90.0,
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: sm.delete_model(ModelName=model_name)))

    config_name = ctx.unique_name("sim2real-aibench-epc-")
    sm.create_endpoint_config(
        EndpointConfigName=config_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "InitialInstanceCount": 1,
                "InstanceType": "ml.m5.large",
                "InitialVariantWeight": 1.0,
            }
        ],
        Tags=managed_tags,
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: sm.delete_endpoint_config(EndpointConfigName=config_name)))

    endpoint_name = ctx.unique_name("sim2real-bench-target-")
    sm.create_endpoint(EndpointName=endpoint_name, EndpointConfigName=config_name, Tags=managed_tags)
    ctx.on_cleanup(lambda: _delete_endpoint_when_settled(sm, endpoint_name))

    # CreateAIBenchmarkJob rejects a BenchmarkTarget endpoint that exists but is not yet
    # InService, so the wait is a real prerequisite, not incidental to this check's lifecycle.
    in_service = _poll_until(
        lambda: sm.describe_endpoint(EndpointName=endpoint_name),
        lambda d: d["EndpointStatus"] in ("InService", "Failed"),
        timeout_s=_budget_s(ctx, _ENDPOINT_TIMEOUT_S),
        interval_s=15.0,
    )
    assert in_service["EndpointStatus"] == "InService", (
        f"target endpoint {endpoint_name!r} never reached InService, got "
        f"{in_service['EndpointStatus']!r} ({in_service.get('FailureReason')})"
    )
    return bucket, endpoint_name


def _create_sagemaker_execution_role(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-exec-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust_policy),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}, {"Key": "sim2real:check", "Value": CHECK}],
    )
    role_arn = resp["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup() -> None:
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    _poll_until(lambda: iam.get_role(RoleName=role_name)["Role"]["Arn"], lambda a: a == role_arn, timeout_s=30.0, interval_s=2.0)
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
