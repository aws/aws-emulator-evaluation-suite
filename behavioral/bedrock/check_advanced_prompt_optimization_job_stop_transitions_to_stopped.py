"""advanced-prompt-optimization-job-stop-transitions-to-stopped."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags

CHECK = "advanced-prompt-optimization-job-stop-transitions-to-stopped"
GROUP = "state-machine"
SERVICES = ["bedrock"]


_TERMINAL_STATUSES = frozenset({"Completed", "Failed", "PartiallyCompleted", "Stopped", "Deleting"})


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StopAdvancedPromptOptimizationJob on a freshly-started job transitions its
    status to Stopped as observed through GetAdvancedPromptOptimizationJob."""
    bedrock = ctx.client("bedrock")
    bucket = _create_bucket(ctx)
    s3 = ctx.client("s3")
    prompt_records = "\n".join(
        json.dumps({
            "version": "bedrock-2026-05-14",
            "templateId": f"sample-{i}",
            "promptTemplate": f"Summarize sample text number {i}: {{{{input}}}}",
            "evaluationSamples": [{"inputVariables": [{"input": f"text {i}"}]}],
        })
        for i in range(10)
    ).encode()
    s3.put_object(Bucket=bucket, Key="apo/input.jsonl", Body=prompt_records)
    model_arn = _first_on_demand_text_model_arn(bedrock)

    job_name = ctx.unique_name("sim2real-apojob-")
    create_resp = _retry_transient(
        lambda: bedrock.create_advanced_prompt_optimization_job(
            jobName=job_name,
            inputConfig={"s3Uri": f"s3://{bucket}/apo/input.jsonl"},
            outputConfig={"s3Uri": f"s3://{bucket}/apo-out/"},
            modelConfigurations=[{"modelId": model_arn}],
            tags=[{"key": "sim2real", "value": "advanced-prompt-optimization-job-stop-transitions-to-stopped"}],
        )
    )
    job_arn = create_resp["jobArn"]
    ctx.on_cleanup(lambda: _best_effort_stop(bedrock, job_arn))

    initial_status = bedrock.get_advanced_prompt_optimization_job(jobIdentifier=job_arn)["jobStatus"]
    assert initial_status not in _TERMINAL_STATUSES, (
        f"expected the freshly-created job to still be running before Stop was ever called, "
        f"but GetAdvancedPromptOptimizationJob already reports jobStatus={initial_status!r}"
    )

    bedrock.stop_advanced_prompt_optimization_job(jobIdentifier=job_arn)

    def _probe():
        return bedrock.get_advanced_prompt_optimization_job(jobIdentifier=job_arn)["jobStatus"]

    final_status = _poll_until(
        _probe, lambda s: s in _TERMINAL_STATUSES, timeout_s=600.0, interval_s=15.0
    )
    assert final_status == "Stopped", (
        f"expected StopAdvancedPromptOptimizationJob to drive the job to Stopped, "
        f"but it reached terminal status {final_status!r} instead"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _create_bucket(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bedrock-").lower().replace("_", "-")
    region = ctx.region
    # us-east-1 is the one region S3 rejects an explicit LocationConstraint for.
    if region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": region}
        )
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": [
        {"Key": "sim2real", "Value": "advanced-prompt-optimization-job-stop-transitions-to-stopped"}]})

    def _cleanup():
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        for o in objs:
            s3.delete_object(Bucket=bucket, Key=o["Key"])
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _retry_transient(fn, timeout_s=60.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("AccessDeniedException", "ValidationException"):
                last_exc = e
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


def _first_on_demand_text_model_arn(bedrock):
    resp = bedrock.list_foundation_models(byOutputModality="TEXT", byInferenceType="ON_DEMAND")
    summaries = [
        m
        for m in resp.get("modelSummaries", [])
        if m.get("modelLifecycle", {}).get("status") == "ACTIVE"
    ]
    if not summaries:
        raise AssertionError(
            "no ACTIVE on-demand text foundation model available in this account/region "
            "to run prompt optimization against"
        )
    return summaries[0]["modelArn"]


def _best_effort_stop(bedrock, job_arn):
    """Stop a job the run left running; a terminal or missing job needs nothing."""
    from botocore.exceptions import ClientError

    try:
        status = bedrock.get_advanced_prompt_optimization_job(jobIdentifier=job_arn)["jobStatus"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status not in _TERMINAL_STATUSES:
        bedrock.stop_advanced_prompt_optimization_job(jobIdentifier=job_arn)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
