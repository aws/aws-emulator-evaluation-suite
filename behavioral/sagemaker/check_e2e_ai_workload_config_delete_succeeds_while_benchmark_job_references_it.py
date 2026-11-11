"""e2e-ai-workload-config-delete-succeeds-while-benchmark-job-references-it."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-ai-workload-config-delete-succeeds-while-benchmark-job-references-it"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

# Registry accounts of the built-in-algorithm ECR images. The "knn" image in MultiModel mode loads
# models lazily on first invoke, so the endpoint reaches InService without a trained artifact; a bare
# inference image with no ModelDataUrl fails its health check and the endpoint goes Failed.
_BUILTIN_ALGO_REGISTRY = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "ap-northeast-1": "351501993468",
    "ap-northeast-2": "835164637446",
    "ap-south-1": "991648021394",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "712309505854",
    "ca-central-1": "469771592824",
    "eu-central-1": "664544806723",
    "eu-north-1": "669576153137",
    "eu-west-1": "438346466558",
    "eu-west-2": "644912444149",
    "eu-west-3": "749696950732",
    "sa-east-1": "855470959533",
}


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAIWorkloadConfig succeeds while a live AIBenchmarkJob still references the config:
    the config is then ResourceNotFound, the dangling job stays describable, and the job deletes
    only after Stop (an InProgress delete is rejected with ValidationException).
    """
    # One teardown deadline per run, started by the first teardown that runs.
    teardown_deadline: dict = {}
    account_id = _BUILTIN_ALGO_REGISTRY.get(ctx.region)
    if account_id is None:
        raise AssertionError(
            f"region {ctx.region!r} is not in the curated built-in-algorithm ECR registry "
            "map this check uses to source a real, cheap-to-boot inference container"
        )

    sm = ctx.client("sagemaker")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")

    config_name = ctx.unique_name("sim2real-aiworkload-")
    job_name = ctx.unique_name("sim2real-aibenchmark-")
    # "sagemaker" in the bucket name matters, not just cosmetics: AmazonSageMakerFullAccess's
    # S3 statements are scoped to bucket names matching that pattern, and the role below has no
    # other S3 grant.
    bucket = ctx.unique_name("sim2real-sagemaker-aibench-out-").lower().replace("_", "-")
    model_name = ctx.unique_name("sim2real-aibench-model-")
    endpoint_config_name = ctx.unique_name("sim2real-aibench-epc-")
    endpoint_name = ctx.unique_name("sim2real-aibench-ep-")
    role_arn = _create_minimal_role(ctx, iam, "sagemaker.amazonaws.com")
    _create_bucket(ctx, s3, bucket)
    # MultiModel CreateModel synchronously validates that ModelDataUrl is a reachable S3 prefix
    # ("Could not access model data"), so the prefix needs at least a placeholder object.
    s3.put_object(Bucket=bucket, Key="mme-models/.keep", Body=b"")

    # A fresh role can transiently fail IAM propagation on the first SageMaker call using it.
    _retry_role_propagation(
        lambda: sm.create_model(
            ModelName=model_name,
            ExecutionRoleArn=role_arn,
            Containers=[
                {
                    "Image": f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/knn:1",
                    "ModelDataUrl": f"s3://{bucket}/mme-models/",
                    "Mode": "MultiModel",
                }
            ],
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: sm.delete_model(ModelName=model_name)))

    sm.create_endpoint_config(
        EndpointConfigName=endpoint_config_name,
        ProductionVariants=[
            {
                "VariantName": "AllTraffic",
                "ModelName": model_name,
                "InstanceType": "ml.m5.large",
                "InitialInstanceCount": 1,
            }
        ],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: _best_effort(lambda: sm.delete_endpoint_config(EndpointConfigName=endpoint_config_name))
    )

    sm.create_endpoint(
        EndpointName=endpoint_name,
        EndpointConfigName=endpoint_config_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_endpoint(sm, endpoint_name, teardown_deadline))

    # Failed is terminal so a broken endpoint reports its FailureReason instead of timing out.
    endpoint_status, failure_reason = _poll_endpoint_status(
        sm, endpoint_name, {"InService", "Failed"}, timeout_s=900.0, interval_s=15.0
    )
    assert endpoint_status == "InService", (
        f"endpoint {endpoint_name!r} did not reach InService: {failure_reason}"
    )

    sm.create_ai_workload_config(
        AIWorkloadConfigName=config_name,
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _delete_ai_workload_config_if_present(sm, config_name))

    # CreateAIBenchmarkJob's own AssumeRole check can lag even after CreateModel used the role
    # ("Unable to assume the provided RoleArn").
    _retry_role_propagation(
        lambda: sm.create_ai_benchmark_job(
            AIBenchmarkJobName=job_name,
            BenchmarkTarget={"Endpoint": {"Identifier": endpoint_name}},
            OutputConfig={"S3OutputLocation": f"s3://{bucket}/benchmark-results/"},
            AIWorkloadConfigIdentifier=config_name,
            RoleArn=role_arn,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        ),
        timeout_s=300.0,
    )
    ctx.on_cleanup(lambda: _delete_ai_benchmark_job_if_present(sm, job_name, teardown_deadline))

    # Precondition: the reference is live, so the delete below is not vacuous.
    described_job = sm.describe_ai_benchmark_job(AIBenchmarkJobName=job_name)
    assert described_job.get("AIWorkloadConfigIdentifier") == config_name or config_name in str(
        described_job.get("AIWorkloadConfigArn", "")
    ), (
        f"expected AIBenchmarkJob {job_name!r} to name AIWorkloadConfig {config_name!r}; "
        f"DescribeAIBenchmarkJob returned {described_job!r}"
    )
    before_delete = sm.describe_ai_workload_config(AIWorkloadConfigName=config_name)
    assert before_delete["AIWorkloadConfigArn"], (
        f"expected {config_name!r} to be describable before the delete, got {before_delete!r}"
    )

    # AWS does not enforce the reference: the delete succeeds rather than ResourceInUse.
    sm.delete_ai_workload_config(AIWorkloadConfigName=config_name)

    gone_code, gone_message = _error(
        lambda: sm.describe_ai_workload_config(AIWorkloadConfigName=config_name)
    )
    assert gone_code == "ResourceNotFound", (
        f"expected {config_name!r} to be gone after the unenforced delete, got {gone_code!r}"
    )
    expected = f"AIWorkloadConfig '{config_name}' not found."
    assert gone_message == expected, f"expected {expected!r}, got {gone_message!r}"

    # The referencing job is left dangling: still describable, naming a deleted config.
    dangling = sm.describe_ai_benchmark_job(AIBenchmarkJobName=job_name)
    assert dangling["AIBenchmarkJobName"] == job_name, (
        f"expected AIBenchmarkJob {job_name!r} to survive the deletion of the config it "
        f"references, got {dangling!r}"
    )

    # A running job cannot be deleted (ValidationException, "Only Completed, Failed, or Stopped
    # jobs can be deleted"), so the order is Stop -> terminal -> Delete. A new job first reports
    # Pending, so the rejected delete waits for InProgress.
    status = _poll_until(
        lambda: sm.describe_ai_benchmark_job(AIBenchmarkJobName=job_name).get("AIBenchmarkJobStatus"),
        lambda st: st == "InProgress" or st in _TERMINAL_BENCHMARK_STATUSES,
        timeout_s=300.0,
        interval_s=2.0,
    )
    assert status == "InProgress", f"expected AIBenchmarkJob {job_name!r} to reach InProgress, got {status!r}"
    running_delete_code, running_delete_message = _error(
        lambda: sm.delete_ai_benchmark_job(AIBenchmarkJobName=job_name)
    )
    assert running_delete_code == "ValidationException", (
        f"expected DeleteAIBenchmarkJob on an InProgress job to be rejected with "
        f"ValidationException, got {running_delete_code!r}"
    )
    expected = (
        "AIBenchmarkJob is in state 'InProgress' and cannot be deleted. "
        "Only Completed, Failed, or Stopped jobs can be deleted."
    )
    assert running_delete_message == expected, f"expected {expected!r}, got {running_delete_message!r}"

    _stop_and_wait_terminal(sm, job_name)
    sm.delete_ai_benchmark_job(AIBenchmarkJobName=job_name)
    benchmark_gone_code, benchmark_gone_message = _error(
        lambda: sm.describe_ai_benchmark_job(AIBenchmarkJobName=job_name)
    )
    assert benchmark_gone_code == "ResourceNotFound", (
        f"deleted AIBenchmarkJob {job_name!r} must be gone from DescribeAIBenchmarkJob; "
        f"got {benchmark_gone_code!r}"
    )
    expected = f"AIBenchmarkJob '{job_name}' not found."
    assert benchmark_gone_message == expected, f"expected {expected!r}, got {benchmark_gone_message!r}"

    # A second delete of the dead id must not silently succeed.
    redelete_code, redelete_message = _error(
        lambda: sm.delete_ai_workload_config(AIWorkloadConfigName=config_name)
    )
    assert redelete_code == "ResourceNotFound", (
        f"deleting the already-deleted AIWorkloadConfig {config_name!r} again must return "
        f"ResourceNotFound, not succeed silently; got {redelete_code!r}"
    )
    # The message embeds a per-call request id and the service's own SDK attempt count, so only
    # the fixed prefix and the attempt-count marker are pinned.
    prefix = f"AIWorkloadConfig '{config_name}' not found. (Service: SageMakerLumen, Status Code: 400, Request ID: "
    assert redelete_message.startswith(prefix) and ") (SDK Attempt Count: " in redelete_message, (
        f"expected {prefix!r}<request id>) (SDK Attempt Count: <n>), got {redelete_message!r}"
    )


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition never became true within {timeout_s}s (last={last!r})")


def _poll_endpoint_status(sm, endpoint_name, terminal_statuses, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last_status = None
    while time.monotonic() < deadline:
        desc = sm.describe_endpoint(EndpointName=endpoint_name)
        last_status = desc["EndpointStatus"]
        if last_status in terminal_statuses:
            return last_status, desc.get("FailureReason")
        time.sleep(interval_s)
    raise AssertionError(
        f"endpoint {endpoint_name!r} never reached a terminal status within {timeout_s}s "
        f"(last={last_status!r})"
    )


def _best_effort(fn):
    """Run a teardown delete; return only when the resource is already gone, raise the rest."""
    try:
        fn()
    except ClientError as exc:
        error = exc.response["Error"]
        message = error.get("Message", "").lower()
        if error["Code"] in ("ResourceNotFound", "NoSuchBucket"):
            return
        if error["Code"] != "ValidationException" or not (
            "could not find" in message or "does not exist" in message
        ):
            raise


# budget.cleanup_timeout for behavioral/sagemaker, one deadline shared by every teardown of a run.
_TEARDOWN_RETRY_S = 1200.0


def _teardown_deadline(teardown_deadline) -> float:
    # A margin inside the budget, so a teardown raises its own error before the runner gives up.
    return teardown_deadline.setdefault("t", time.monotonic() + _TEARDOWN_RETRY_S - 120.0)


def _delete_endpoint(sm, endpoint_name: str, teardown_deadline) -> None:
    """Teardown DeleteEndpoint: an endpoint still Creating/Updating is refused with
    ValidationException "Cannot update in-progress endpoint", retried every 2 s to the shared
    cleanup deadline; the not-found answer is done (via _best_effort), the rest raise."""
    deadline = _teardown_deadline(teardown_deadline)
    while True:
        try:
            _best_effort(lambda: sm.delete_endpoint(EndpointName=endpoint_name))
            return
        except ClientError as exc:
            error = exc.response["Error"]
            in_progress = error["Code"] == "ValidationException" and error.get("Message", "").startswith(
                "Cannot update in-progress endpoint"
            )
            if not in_progress or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _create_bucket(ctx, s3, bucket: str) -> None:
    kwargs = {"Bucket": bucket}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)

    def _cleanup() -> None:
        def _empty() -> None:
            paginator = s3.get_paginator("list_objects_v2")
            for page in paginator.paginate(Bucket=bucket):
                for obj in page.get("Contents", []):
                    s3.delete_object(Bucket=bucket, Key=obj["Key"])

        _best_effort(_empty)
        _best_effort(lambda: s3.delete_bucket(Bucket=bucket))

    ctx.on_cleanup(_cleanup)


def _error(fn):
    """Call fn(); return its botocore error code and message. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _try_delete_workload_config(sm, name) -> bool:
    try:
        sm.delete_ai_workload_config(AIWorkloadConfigName=name)
        return True
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceInUse":
            return False
        raise


def _retry_role_propagation(fn, *, timeout_s: float = 120.0, interval_s: float = 5.0):
    """Retry fn() while it fails with a role-related ValidationException/AccessDeniedException
    (IAM propagation of a just-created role), bounded by a deadline."""
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            message = exc.response["Error"].get("Message", "")
            if code in ("ValidationException", "AccessDeniedException") and "role" in message.lower():
                last_exc = exc
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _create_minimal_role(ctx, iam, service_principal: str) -> str:
    import json

    role_name = ctx.unique_name("sim2real-sm-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": service_principal},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    resp = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    # Cleanups run last-registered first: the detach must run before DeleteRole, which refuses
    # a role with attached policies (DeleteConflict).
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.attach_role_policy(
        RoleName=role_name,
        PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess",
    )
    ctx.on_cleanup(lambda: iam.detach_role_policy(
        RoleName=role_name, PolicyArn="arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    ))
    return resp["Role"]["Arn"]


def _delete_ai_workload_config_if_present(sm, name):
    try:
        sm.delete_ai_workload_config(AIWorkloadConfigName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


_TERMINAL_BENCHMARK_STATUSES = ("Completed", "Failed", "Stopped")


def _stop_and_wait_terminal(sm, job_name, *, timeout_s: float = 600.0, interval_s: float = 10.0):
    """Stop the job and wait for a status DeleteAIBenchmarkJob accepts.

    An already-terminal job's StopAIBenchmarkJob is a benign no-op/rejection, so only the wait
    is load-bearing; running out of the window is a FAIL, not a swallowed skip.
    """
    try:
        sm.stop_ai_benchmark_job(AIBenchmarkJobName=job_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ValidationException", "ResourceNotFound"):
            raise
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = sm.describe_ai_benchmark_job(AIBenchmarkJobName=job_name).get(
            "AIBenchmarkJobStatus"
        )
        if last in _TERMINAL_BENCHMARK_STATUSES:
            return last
        time.sleep(interval_s)
    raise AssertionError(
        f"AIBenchmarkJob {job_name!r} never reached a deletable terminal status within "
        f"{timeout_s}s (last={last!r})"
    )


def _delete_ai_benchmark_job_if_present(sm, name, teardown_deadline):
    """Teardown: a running AIBenchmarkJob cannot be deleted, so stop it and wait first."""
    try:
        sm.describe_ai_benchmark_job(AIBenchmarkJobName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "ResourceNotFound":
            return
        raise
    _stop_and_wait_terminal(sm, name, timeout_s=max(1.0, _teardown_deadline(teardown_deadline) - time.monotonic()))
    try:
        sm.delete_ai_benchmark_job(AIBenchmarkJobName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

