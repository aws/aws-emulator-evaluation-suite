"""sampling-operation-generates-text-from-running-session."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "sampling-operation-generates-text-from-running-session"
GROUP = "sampling-operations"
SERVICES = ["sagemakertrainingsessionruntime"]

_BASE_MODEL_PATH = "hub-content/SageMakerPublicHub/Model/openai-reasoning-gpt-oss-20b/3.43.2"
_PROMPT_TOKENS = [791, 6864, 315, 9822, 374]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises; only ``not_found`` codes pass."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _delete_model_package_group_and_context(sm, group_name: str, group_arn: str) -> None:
    """Deletes the group and the lineage Context SageMaker creates for it on first use."""
    try:
        sm.delete_model_package_group(ModelPackageGroupName=group_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFound":
            raise
    for ctx_summary in sm.list_contexts(SourceUri=group_arn)["ContextSummaries"]:
        sm.delete_context(ContextName=ctx_summary["ContextName"])


def _wait_for_session_status(sm, session_name: str, *, until: set[str], budget_s: float = 120.0):
    """Polls DescribeTrainingSession until its status is one of ``until``."""
    deadline = time.monotonic() + budget_s
    while True:
        detail = sm.describe_training_session(TrainingSessionName=session_name)[
            "TrainingSessionDetail"
        ]
        status = detail["TrainingSessionStatus"]
        if status in until:
            return detail
        assert time.monotonic() < deadline, (
            f"training session stuck at status {status!r}, expected one of {sorted(until)}"
        )
        time.sleep(3)


def _execute_sampling_operation_when_ready(tsr, session_name: str, *, budget_s: float = 120.0):
    """Submits a sampling operation, retrying the documented warm-up ConflictException.

    A session reports ``Running`` before its GPU backend accepts operations; AWS answers the
    first call with ``ConflictException`` ("Session is not yet available") until it does.
    """
    deadline = time.monotonic() + budget_s
    while True:
        try:
            return tsr.execute_sampling_operation(
                trainingSessionName=session_name,
                operationConfig={
                    "sample": {
                        "prompt": {"chunks": [{"tokens": _PROMPT_TOKENS, "type": "encoded_text"}]},
                        "numSamples": 1,
                        "samplingParams": {"maxTokens": 512, "temperature": 0.7},
                    }
                },
            )
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(5)


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """ExecuteSamplingOperation against a running training session generates real completion
    tokens, and GetSamplingOperationResult reports the terminal status and usage that produced
    them.

    Reference: https://docs.aws.amazon.com/sagemaker/latest/dg/customizing-models-training-sessions.html
    """
    iam = ctx.client("iam")
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")
    tsr = ctx.client("sagemakertrainingsessionruntime")

    role_name = ctx.unique_name("sim2real-behav-tsr-role-")
    bucket_name = ctx.unique_name("sim2real-behav-tsr-out-")
    group_name = ctx.unique_name("sim2real-behav-tsr-mpg-")
    session_name = ctx.unique_name("sim2real-behav-tsr-sess-")

    trust_policy = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "training-session.sagemaker.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }],
    }
    role = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust_policy)
    )["Role"]
    ctx.on_cleanup(_teardown(lambda: iam.delete_role(RoleName=role_name), "NoSuchEntity"))
    partition = role["Arn"].split(":")[1]
    public_hub = f"arn:{partition}:sagemaker:{ctx.region}:aws"
    base_model_arn = f"{public_hub}:{_BASE_MODEL_PATH}"

    bucket_args = {"Bucket": bucket_name}
    # us-east-1 is the one region CreateBucket rejects an explicit LocationConstraint for.
    if ctx.region != "us-east-1":
        bucket_args["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**bucket_args)
    ctx.on_cleanup(_teardown(lambda: s3.delete_bucket(Bucket=bucket_name), "NoSuchBucket"))

    session_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject", "s3:ListBucket"],
                "Resource": [
                    f"arn:{partition}:s3:::{bucket_name}",
                    f"arn:{partition}:s3:::{bucket_name}/*",
                ],
            },
            {
                "Effect": "Allow",
                "Action": ["sagemaker:DescribeHubContent"],
                "Resource": [
                    f"{public_hub}:hub/SageMakerPublicHub",
                    f"{public_hub}:hub-content/SageMakerPublicHub/Model/*",
                ],
            },
            {
                "Effect": "Allow",
                "Action": ["sagemaker:DescribeModelPackageGroup"],
                "Resource": "*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName="session-access", PolicyDocument=json.dumps(session_policy)
    )
    ctx.on_cleanup(
        _teardown(
            lambda: iam.delete_role_policy(RoleName=role_name, PolicyName="session-access"),
            "NoSuchEntity",
        )
    )

    sm.create_model_package_group(ModelPackageGroupName=group_name)
    group_arn = f"arn:{partition}:sagemaker:{ctx.region}:{ctx.account}:model-package-group/{group_name}"
    ctx.on_cleanup(
        lambda: _delete_model_package_group_and_context(sm, group_name, group_arn)
    )

    # IAM propagation: the role is not yet assumable by the service right after creation.
    create_deadline = time.monotonic() + 120.0
    while True:
        try:
            sm.create_training_session(
                TrainingSessionName=session_name,
                LoraConfig={"Rank": 8, "Alpha": 16},
                RoleArn=role["Arn"],
                ModelConfig={"BaseModelArn": base_model_arn, "AcceptEula": True},
                OutputConfig={"S3Location": {"Path": f"s3://{bucket_name}/out/"}},
                ModelPackageGroupArn=group_arn,
            )
            break
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            msg = exc.response["Error"]["Message"]
            not_yet_assumable = code == "ValidationException" and "Could not assume execution role" in msg
            if not not_yet_assumable or time.monotonic() >= create_deadline:
                raise
            time.sleep(5)
    ctx.on_cleanup(_teardown(lambda: sm.delete_training_session(TrainingSessionName=session_name),
                              "ResourceNotFound"))

    def _stop_session() -> None:
        try:
            sm.stop_training_session(TrainingSessionName=session_name)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFound":
                raise
            return
        _wait_for_session_status(sm, session_name, until={"Stopped"})

    ctx.on_cleanup(_stop_session)

    detail = _wait_for_session_status(sm, session_name, until={"Running"})
    assert detail["TrainingSessionStatus"] == "Running", (
        f"expected the session to reach Running, got {detail['TrainingSessionStatus']!r}"
    )

    submitted = _execute_sampling_operation_when_ready(tsr, session_name)
    operation_id = submitted["operationId"]
    assert operation_id, "ExecuteSamplingOperation returned no operationId"

    deadline = time.monotonic() + 180.0
    while True:
        result = tsr.get_sampling_operation_result(
            trainingSessionName=session_name, operationId=operation_id
        )
        status = result["status"]
        if status != "InProgress":
            break
        assert time.monotonic() < deadline, f"sampling operation stuck at {status!r}"
        time.sleep(3)

    assert status == "Completed", f"expected the sampling operation to complete, got {status!r}"
    sequences = result["operationResult"]["sample"]["sequences"]
    assert len(sequences) == 1, f"expected 1 generated sequence, got {len(sequences)}"
    tokens = sequences[0]["tokens"]
    assert len(tokens) > 0, "the completed sampling operation carried no generated tokens"
    assert sequences[0]["stopReason"] in ("stop", "length"), (
        f"unexpected stopReason {sequences[0]['stopReason']!r}"
    )
    usage = sequences[0]["tokenUsage"]
    assert usage["decode"] == len(tokens), (
        f"decode token count {usage['decode']!r} should match the {len(tokens)} generated tokens"
    )
    assert usage["prefill"] == len(_PROMPT_TOKENS), (
        f"prefill token count {usage['prefill']!r} should match the {len(_PROMPT_TOKENS)}-token prompt"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
