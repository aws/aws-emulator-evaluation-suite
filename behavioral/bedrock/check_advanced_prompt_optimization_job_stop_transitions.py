"""advanced-prompt-optimization-job-stop-transitions."""
from __future__ import annotations

import json
import time
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "advanced-prompt-optimization-job-stop-transitions"
GROUP = "state-machine"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateAdvancedPromptOptimizationJob starts a job; Stop drives it to Stopped."""
    bedrock = ctx.client("bedrock")
    bucket = _create_scratch_bucket(ctx)
    input_key = "apo-input/prompts.jsonl"
    _upload_input(ctx, bucket, input_key)

    job_name = ctx.unique_name("sim2real-apojob-")
    model_arn = _first_on_demand_text_model_arn(bedrock)

    resp = bedrock.create_advanced_prompt_optimization_job(
        jobName=job_name,
        inputConfig={"s3Uri": f"s3://{bucket}/{input_key}"},
        outputConfig={"s3Uri": f"s3://{bucket}/apo-output/"},
        modelConfigurations=[{"modelId": model_arn}],
    )
    job_arn = resp["jobArn"]
    ctx.on_cleanup(lambda: _stop_if_running(bedrock, job_arn))

    initial = bedrock.get_advanced_prompt_optimization_job(jobIdentifier=job_arn)
    assert initial["jobStatus"] in ("InProgress", "Stopping", "Stopped", "Completed", "Failed")

    bedrock.stop_advanced_prompt_optimization_job(jobIdentifier=job_arn)

    terminal = ("Stopped", "Completed", "Failed")
    state = _poll_until(
        lambda: bedrock.get_advanced_prompt_optimization_job(jobIdentifier=job_arn),
        lambda r: r["jobStatus"] in terminal,
        timeout_s=600.0,
        interval_s=10.0,
    )
    assert state["jobStatus"] == "Stopped", f"job ended in {state['jobStatus']!r}, expected Stopped"
    assert state["jobArn"] == job_arn


def _bucket_policy(bucket: str, account: str, region: str) -> str:
    return json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "AmazonBedrockAdvancedPromptOptimizationAccess",
                    "Effect": "Allow",
                    "Principal": {"Service": "bedrock.amazonaws.com"},
                    "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                    "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
                    "Condition": {
                        "StringEquals": {"aws:SourceAccount": account},
                        "ArnLike": {"aws:SourceArn": f"arn:aws:bedrock:{region}:{account}:*"},
                    },
                }
            ],
        }
    )


def _create_scratch_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-bedrock-apo-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    s3.put_bucket_tagging(
        Bucket=bucket, Tagging={"TagSet": [{"Key": "sim2real", "Value": "bedrock-apo"}]}
    )
    account = ctx.client("sts").get_caller_identity()["Account"]
    s3.put_bucket_policy(Bucket=bucket, Policy=_bucket_policy(bucket, account, ctx.region))

    def _cleanup() -> None:
        try:
            objs = s3.list_objects_v2(Bucket=bucket).get("Contents", [])
            if objs:
                failed = s3.delete_objects(
                    Bucket=bucket, Delete={"Objects": [{"Key": o["Key"]} for o in objs]}
                ).get("Errors")
                if failed:
                    raise RuntimeError(f"DeleteObjects left {len(failed)} object(s): {failed[:3]}")
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket


def _upload_input(ctx, bucket: str, key: str) -> None:
    s3 = ctx.client("s3")
    # Each record is a prompt template in the input schema the job validates entry by entry.
    lines = [
        json.dumps(
            {
                "version": "bedrock-2026-05-14",
                "templateId": f"sample-{i}",
                "promptTemplate": f"Explain topic {i} of Amazon Bedrock: {{{{input}}}}",
                "evaluationSamples": [{"inputVariables": [{"input": f"inference profiles {i}"}]}],
            }
        )
        for i in range(10)
    ]
    s3.put_object(Bucket=bucket, Key=key, Body="\n".join(lines).encode("utf-8"))


def _first_on_demand_text_model_arn(bedrock) -> str:
    """An ACTIVE on-demand text model, since Bedrock retires and re-gates individual models."""
    resp = bedrock.list_foundation_models(byOutputModality="TEXT", byInferenceType="ON_DEMAND")
    summaries = [
        m
        for m in resp.get("modelSummaries", [])
        if m.get("modelLifecycle", {}).get("status") == "ACTIVE"
    ]
    if not summaries:
        raise AssertionError("no ACTIVE on-demand text foundation model in this account/region")
    return summaries[0]["modelArn"]


def _stop_if_running(bedrock, job_arn: str) -> None:
    """Stop a job the run left running; one already terminal needs nothing."""
    status = bedrock.get_advanced_prompt_optimization_job(jobIdentifier=job_arn)["jobStatus"]
    if status in ("InProgress", "Submitted", "Pending"):
        bedrock.stop_advanced_prompt_optimization_job(jobIdentifier=job_arn)


def _poll_until(probe: Callable[[], Any], predicate: Callable[[Any], bool], *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
