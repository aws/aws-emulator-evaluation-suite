"""advanced-prompt-optimization-job-lifecycle."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "advanced-prompt-optimization-job-lifecycle"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAdvancedPromptOptimizationJob starts InProgress and
    StopAdvancedPromptOptimizationJob on the running job drives it to the terminal Stopped
    state."""
    bedrock = ctx.client("bedrock")
    model_arn = _first_on_demand_text_model_arn(bedrock)

    bucket = _create_scratch_bucket(ctx)
    input_key = "apo-input/prompts.jsonl"
    _upload_input(ctx, bucket, input_key)
    job_name = ctx.unique_name("sim2real-apo-")

    created = bedrock.create_advanced_prompt_optimization_job(
        jobName=job_name,
        inputConfig={"s3Uri": f"s3://{bucket}/{input_key}"},
        outputConfig={"s3Uri": f"s3://{bucket}/apo-output/"},
        modelConfigurations=[{"modelId": model_arn}],
    )
    job_arn = created["jobArn"]
    ctx.on_cleanup(lambda: _try_stop(bedrock, job_arn))

    def _probe_started():
        return bedrock.get_advanced_prompt_optimization_job(jobIdentifier=job_arn)

    # Stop must hit a running job: wait (bounded) for the job to report its first status.
    started = _poll_until(
        _probe_started,
        lambda r: r["jobStatus"] in ("InProgress", "Completed", "Failed", "PartiallyCompleted"),
        timeout_s=120.0,
    )
    assert started["jobStatus"] == "InProgress", f"job started in unexpected state {started['jobStatus']!r}"

    bedrock.stop_advanced_prompt_optimization_job(jobIdentifier=job_arn)

    def _probe_stopped():
        return bedrock.get_advanced_prompt_optimization_job(jobIdentifier=job_arn)

    final = _poll_until(
        _probe_stopped,
        lambda r: r["jobStatus"] in ("Stopped", "Completed", "Failed", "PartiallyCompleted"),
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert final["jobStatus"] == "Stopped", f"job ended in {final['jobStatus']!r} instead of Stopped"


def _create_scratch_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bedrock-apo-").lower().replace("_", "-")
    # us-east-1 is the only region where CreateBucket rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]}
    )

    def _cleanup() -> None:
        objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
        if objs:
            failed = s3.delete_objects(
                Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
            ).get("Errors")
            if failed:
                raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
        s3.delete_bucket(Bucket=bucket)

    ctx.on_cleanup(_cleanup)
    return bucket


def _upload_input(ctx, bucket: str, key: str) -> None:
    s3 = ctx.client("s3")
    lines = [
        json.dumps(
            {
                "version": "bedrock-2026-05-14",
                "templateId": f"sample-template-{i}",
                "promptTemplate": f"Summarize the key point of sample document: {{{{document_{i}}}}}",
                "evaluationSamples": [
                    {"inputVariables": [{f"document_{i}": f"This is sample document {i}."}]}
                ],
            }
        )
        for i in range(5)
    ]
    s3.put_object(Bucket=bucket, Key=key, Body="\n".join(lines).encode("utf-8"))


def _first_on_demand_text_model_arn(bedrock) -> str:
    resp = bedrock.list_foundation_models(byOutputModality="TEXT", byInferenceType="ON_DEMAND")
    summaries = [
        m
        for m in resp.get("modelSummaries", [])
        if m.get("modelLifecycle", {}).get("status") == "ACTIVE"
    ]
    if not summaries:
        raise AssertionError(
            "no ACTIVE on-demand text foundation model available in this account/region "
            "to run advanced prompt optimization against"
        )
    return summaries[0]["modelArn"]


def _try_stop(bedrock, job_arn) -> None:
    """Stop a job the run left running; a terminal or missing job needs nothing."""
    try:
        status = bedrock.get_advanced_prompt_optimization_job(jobIdentifier=job_arn)["jobStatus"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            return
        raise
    if status not in ("Completed", "Failed", "PartiallyCompleted", "Stopping", "Stopped", "Deleting"):
        bedrock.stop_advanced_prompt_optimization_job(jobIdentifier=job_arn)


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
