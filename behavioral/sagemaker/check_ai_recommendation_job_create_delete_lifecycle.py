"""ai-recommendation-job-create-delete-lifecycle."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "ai-recommendation-job-create-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

#: Fresh jobs tried for one that is read InProgress and then stopped, before failing.
_LIFECYCLE_ATTEMPTS = 3
#: Terminal states a job reaches by itself; a job in one never showed the InProgress -> Stopped path.
_ENDED_ON_ITS_OWN = ("Failed", "Completed")


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An AIRecommendationJob starts InProgress, stops to Stopped, and after delete both describe
    and a repeat delete return ResourceNotFound."""
    sm = ctx.client("sagemaker")

    if not hasattr(sm, "create_ai_recommendation_job"):
        raise AssertionError(
            "installed botocore does not expose create_ai_recommendation_job "
            "(SageMaker AI Recommendation Job API not present in this SDK version)"
        )

    role_arn = _create_sagemaker_execution_role(ctx)

    workload_name = ctx.unique_name("sim2real-aiwc-rec-")
    sm.create_ai_workload_config(
        AIWorkloadConfigName=workload_name,
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: sm.delete_ai_workload_config(AIWorkloadConfigName=workload_name)))

    # A job can end on its own (Failed or Completed) before the first read or before the stop lands; such a job
    # never showed the InProgress -> Stopped path, so it is deleted and a fresh one created, up to
    # the attempt cap.
    seen = []
    for _ in range(_LIFECYCLE_ATTEMPTS):
        job_name = ctx.unique_name("sim2real-airec-")
        resp = sm.create_ai_recommendation_job(
            AIRecommendationJobName=job_name,
            ModelSource={"S3": {"S3Uri": f"s3://sim2real-behav-models-{ctx.region}/{job_name}/model.tar.gz"}},
            OutputConfig={"S3OutputLocation": f"s3://sim2real-behav-output-{ctx.region}/{job_name}/"},
            AIWorkloadConfigIdentifier=workload_name,
            PerformanceTarget={"Constraints": [{"Metric": "throughput"}]},
            RoleArn=role_arn,
            Tags=[{"Key": "sim2real:check", "Value": CHECK}],
        )
        arn = resp["AIRecommendationJobArn"]
        cleaned = {"done": False}

        def _cleanup(job_name=job_name, cleaned=cleaned) -> None:
            if not cleaned["done"]:
                _safe_call(lambda: sm.delete_ai_recommendation_job(AIRecommendationJobName=job_name))

        ctx.on_cleanup(_cleanup)

        desc = sm.describe_ai_recommendation_job(AIRecommendationJobName=job_name)
        assert desc["AIRecommendationJobArn"] == arn, f"expected AIRecommendationJobArn {arn!r}, got {desc['AIRecommendationJobArn']!r}"
        status = desc["AIRecommendationJobStatus"]
        if status == "InProgress":
            # DeleteAIRecommendationJob is refused while the job runs; it must be stopped first.
            stop_error = None
            try:
                sm.stop_ai_recommendation_job(AIRecommendationJobName=job_name)
            except ClientError as exc:
                stop_error = exc
            settled = _poll_until(
                lambda: sm.describe_ai_recommendation_job(AIRecommendationJobName=job_name)["AIRecommendationJobStatus"],
                lambda s: s == "Stopped" or s in _ENDED_ON_ITS_OWN,
                timeout_s=120.0,
                interval_s=3.0,
            )
            if settled == "Stopped":
                assert stop_error is None, f"expected the accepted-stop path, but the stop was refused: {stop_error!r}"
                break
            # The job ended on its own before the stop took effect: the same missed window as a job
            # that has already ended before the stop.
            seen.append(("InProgress", f"stop {'refused' if stop_error else 'accepted'}, job {settled}"))
        elif status in _ENDED_ON_ITS_OWN:
            seen.append((status, None))
        else:
            raise AssertionError(
                f"expected a freshly created job to report InProgress before any terminal transition, got {status!r}"
            )
        sm.delete_ai_recommendation_job(AIRecommendationJobName=job_name)
        cleaned["done"] = True
    else:
        raise AssertionError(
            f"every new job ended on its own before it could be stopped, so none showed the InProgress -> "
            f"Stopped path; (first status, stop outcome) per job: {seen}"
        )

    sm.delete_ai_recommendation_job(AIRecommendationJobName=job_name)
    cleaned["done"] = True

    describe_code, describe_message = _error(lambda: sm.describe_ai_recommendation_job(AIRecommendationJobName=job_name))
    assert describe_code == "ResourceNotFound", f"expected ResourceNotFound after delete, got {describe_code!r}"
    assert describe_message == f"Job '{job_name}' not found.", f"unexpected describe-after-delete message: {describe_message!r}"

    # message varies: the repeat-delete message embeds a per-request id and attempt count.
    delete_code, _ = _error(lambda: sm.delete_ai_recommendation_job(AIRecommendationJobName=job_name))
    assert delete_code == "ResourceNotFound", f"expected a second delete on the same id to also return ResourceNotFound, got {delete_code!r}"


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise


def _error(fn):
    """Call fn(); return its error (code, message). A success raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to fail, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


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
        Tags=[{"Key": "sim2real:check", "Value": CHECK}],
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
