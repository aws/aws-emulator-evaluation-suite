"""delete-inference-profile-while-referenced-blocked."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError


CHECK = "delete-inference-profile-while-referenced-blocked"
GROUP = "overly-permissive"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c3", "plane:control")
def run(ctx) -> None:
    """DeleteInferenceProfile succeeds both on an application inference profile that is the modelId
    of an in-flight batch inference job and on an unreferenced sibling profile; GetInferenceProfile (and
    a second delete of the referenced one) then answer ResourceNotFoundException "Inference profile not found."."""
    bedrock = ctx.client("bedrock")
    source_arn = _pick_copyable_source_arn(ctx, bedrock)

    referenced = bedrock.create_inference_profile(
        inferenceProfileName=ctx.unique_name("sim2real-ip-ref-"),
        modelSource={"copyFrom": source_arn},
    )
    referenced_arn = referenced["inferenceProfileArn"]
    ctx.on_cleanup(lambda: _delete_profile(ctx, referenced_arn))

    unreferenced = bedrock.create_inference_profile(
        inferenceProfileName=ctx.unique_name("sim2real-ip-free-"),
        modelSource={"copyFrom": source_arn},
    )
    unreferenced_arn = unreferenced["inferenceProfileArn"]
    ctx.on_cleanup(lambda: _delete_profile(ctx, unreferenced_arn))

    job_arn = _start_batch_inference_job(ctx, referenced_arn)
    # Registered last so it runs first: the job is stopped before its bucket and role go.
    ctx.on_cleanup(lambda: _stop_job_and_wait(ctx, job_arn))

    # The job is genuinely in flight, not already terminal.
    state = bedrock.get_model_invocation_job(jobIdentifier=job_arn)
    assert state["status"] in ("Submitted", "InProgress", "Validating", "Scheduled"), (
        f"job reached unexpected state before the deletion attempt: {state['status']}"
    )

    # Bedrock does not guard an application inference profile that a running job names.
    bedrock.delete_inference_profile(inferenceProfileIdentifier=referenced_arn)
    gone = _error(lambda: bedrock.get_inference_profile(inferenceProfileIdentifier=referenced_arn))
    assert gone == ("ResourceNotFoundException", "Inference profile not found."), (
        f"expected the referenced profile to be gone after the accepted delete, got {gone!r}"
    )
    # The delete took effect: deleting the same profile again is refused as not found.
    again = _error(lambda: bedrock.delete_inference_profile(inferenceProfileIdentifier=referenced_arn))
    assert again == ("ResourceNotFoundException", "Inference profile not found."), (
        f"expected a second delete of the referenced profile to be refused as not found, got {again!r}"
    )

    # Positive control: an unreferenced profile deletes the same way.
    bedrock.delete_inference_profile(inferenceProfileIdentifier=unreferenced_arn)
    free_gone = _error(lambda: bedrock.get_inference_profile(inferenceProfileIdentifier=unreferenced_arn))
    assert free_gone == ("ResourceNotFoundException", "Inference profile not found."), (
        f"expected the unreferenced profile to be gone after delete, got {free_gone!r}"
    )


def _error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s, last={last}")


def _pick_copyable_source_arn(ctx, bedrock) -> str:
    """A SYSTEM_DEFINED inference profile ARN that can be copied into an application profile.

    Active Amazon models go first: third-party models can need a use-case form before a batch job
    accepts them, and a Legacy model rejects batch jobs outright."""
    profiles = bedrock.list_inference_profiles(typeEquals="SYSTEM_DEFINED").get(
        "inferenceProfileSummaries", []
    )
    assert profiles, "ListInferenceProfiles returned no SYSTEM_DEFINED inference profiles"

    active_amazon_model_arns = {
        m["modelArn"]
        for m in bedrock.list_foundation_models().get("modelSummaries", [])
        if m.get("providerName") == "Amazon"
        and m.get("modelLifecycle", {}).get("status") == "ACTIVE"
    }

    def _tier(profile) -> int:
        model_arns = {m.get("modelArn") for m in profile.get("models", [])}
        if model_arns & active_amazon_model_arns:
            return 0
        if any("foundation-model/amazon." in arn for arn in model_arns if arn):
            return 1
        return 2

    ordered = sorted(profiles, key=_tier)

    last_error = None
    for profile in ordered[:8]:
        candidate_arn = profile["inferenceProfileArn"]
        probe_name = ctx.unique_name("sim2real-ip-probe-")
        try:
            probe = bedrock.create_inference_profile(
                inferenceProfileName=probe_name,
                modelSource={"copyFrom": candidate_arn},
            )
        except Exception as exc:  # noqa: BLE001
            last_error = exc
            continue
        bedrock.delete_inference_profile(
            inferenceProfileIdentifier=probe["inferenceProfileArn"]
        )
        return candidate_arn
    raise AssertionError(f"no usable SYSTEM_DEFINED inference profile found: {last_error}")


def _start_batch_inference_job(ctx, model_id: str):
    bedrock = ctx.client("bedrock")
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    bucket = ctx.unique_name("sim2real-bedrock-bij-").lower().replace("_", "-")
    # S3 quirk, not a region pin: us-east-1 rejects an explicit LocationConstraint.
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region}
        )
    ctx.on_cleanup(lambda: _empty_and_delete_bucket(ctx, bucket))

    records = [
        json.dumps({
            "recordId": f"REC{i:05d}",
            "modelInput": {
                "messages": [
                    {"role": "user", "content": [{"text": f"Say hello, request {i}."}]}
                ],
            },
        })
        for i in range(100)
    ]
    s3.put_object(Bucket=bucket, Key="input/input.jsonl", Body="\n".join(records).encode("utf-8"))

    role_name = ctx.unique_name("sim2real-bij-role-")
    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "bedrock.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {
                "StringEquals": {"aws:SourceAccount": account_id},
                "ArnLike": {
                    "aws:SourceArn": f"arn:aws:bedrock:{ctx.region}:{account_id}:model-invocation-job/*"
                },
            },
        }],
    }
    role = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy))
    role_arn = role["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_role(ctx, role_name))

    access_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [f"arn:aws:s3:::{bucket}", f"arn:aws:s3:::{bucket}/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["bedrock:InvokeModel"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name,
        PolicyName="batch-inference-access",
        PolicyDocument=json.dumps(access_policy),
    )

    def _try_create():
        return bedrock.create_model_invocation_job(
            jobName=ctx.unique_name("sim2real-bij-job-"),
            roleArn=role_arn,
            modelId=model_id,
            modelInvocationType="Converse",
            inputDataConfig={"s3InputDataConfig": {"s3Uri": f"s3://{bucket}/input/input.jsonl"}},
            outputDataConfig={"s3OutputDataConfig": {"s3Uri": f"s3://{bucket}/output/"}},
        )

    # IAM role propagation before Bedrock assumes it -- retry past the
    # transient AccessDenied/ValidationException window.
    last_error: list = [None]

    def _attempt():
        try:
            return _try_create()
        except Exception as exc:  # noqa: BLE001
            code = getattr(exc, "response", {}).get("Error", {}).get("Code")
            message = getattr(exc, "response", {}).get("Error", {}).get("Message")
            last_error[0] = f"{code}: {message}"
            if code in ("AccessDeniedException", "ValidationException"):
                return None
            raise

    try:
        job = _poll_until(_attempt, lambda r: r is not None, timeout_s=120.0, interval_s=10.0)
    except AssertionError:
        detail = last_error[0] or ""
        if "pass role" in detail.lower() or "passrole" in detail.lower():
            raise AssertionError(
                "CreateModelInvocationJob refused to pass the same-account service role: "
                f"{detail}"
            )
        raise AssertionError(
            f"batch inference job never accepted within timeout; last error: {detail}"
        )
    return job["jobArn"]


_JOB_TERMINAL = ("Stopped", "Completed", "PartiallyCompleted", "Failed", "Expired")


def _stop_job_and_wait(ctx, job_arn: str) -> None:
    """Stop the job and wait until it is terminal; a terminal job answers ValidationException."""
    bedrock = ctx.client("bedrock")
    try:
        bedrock.stop_model_invocation_job(jobIdentifier=job_arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code == "ResourceNotFoundException":
            return
        if code != "ValidationException":
            raise
    _poll_until(
        lambda: bedrock.get_model_invocation_job(jobIdentifier=job_arn)["status"],
        lambda status: status in _JOB_TERMINAL,
        timeout_s=600.0,
        interval_s=15.0,
    )


def _delete_role(ctx, role_name: str) -> None:
    iam = ctx.client("iam")
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName="batch-inference-access")
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _empty_and_delete_bucket(ctx, bucket: str) -> None:
    s3 = ctx.client("s3")
    try:
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            objs = page.get("Contents", [])
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


def _delete_profile(ctx, profile_arn: str) -> None:
    bedrock = ctx.client("bedrock")
    try:
        bedrock.delete_inference_profile(inferenceProfileIdentifier=profile_arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
