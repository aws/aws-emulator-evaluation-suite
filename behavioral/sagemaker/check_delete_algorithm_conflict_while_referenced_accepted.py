"""delete-algorithm-conflict-while-referenced-accepted."""
from __future__ import annotations

import json
import time

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "delete-algorithm-conflict-while-referenced-accepted"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteAlgorithm succeeds with no error while a live training job references the algorithm:
    DescribeAlgorithm then answers ValidationException "Algorithm <arn> does not exist.", the job still
    describes and names it, and an unreferenced sibling algorithm deletes with the same answer."""
    sm = ctx.client("sagemaker")
    role_arn = _ensure_execution_role(ctx)

    channels = [{"Name": "training", "SupportedContentTypes": ["text/csv"], "SupportedInputModes": ["File"]}]
    training_spec = {
        # CreateAlgorithm resolves the ECR image at creation time (both a non-ECR string and a
        # syntactically-valid-but-fake ECR URI are rejected with ValidationException, the latter
        # as "Access denied ... check if your ECR image exists and has proper pull permissions").
        # AWS's own built-in XGBoost image is real and publicly pullable, so it satisfies that
        # check without needing a docker build/push of our own.
        "TrainingImage": _xgboost_training_image(ctx.region),
        "SupportedTrainingInstanceTypes": ["ml.m5.large"],
        "TrainingChannels": channels,
    }

    algo_referenced = ctx.unique_name("sim2real-behav-algo-ref-")
    algo_referenced_arn = sm.create_algorithm(
        AlgorithmName=algo_referenced,
        TrainingSpecification=training_spec,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["AlgorithmArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: sm.delete_algorithm(AlgorithmName=algo_referenced)))
    # CreateAlgorithm validates the spec (incl. resolving the image) asynchronously;
    # a training job cannot meaningfully reference it before that validation lands.
    algo_status = _poll_until(
        lambda: sm.describe_algorithm(AlgorithmName=algo_referenced)["AlgorithmStatus"],
        lambda s: s in ("Completed", "Failed"),
        timeout_s=120,
        interval_s=3,
    )
    assert algo_status == "Completed", f"expected {algo_referenced!r} to validate Completed, got {algo_status!r}"

    algo_unreferenced = ctx.unique_name("sim2real-behav-algo-free-")
    algo_unreferenced_arn = sm.create_algorithm(
        AlgorithmName=algo_unreferenced,
        TrainingSpecification=training_spec,
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )["AlgorithmArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: sm.delete_algorithm(AlgorithmName=algo_unreferenced)))
    # DeleteAlgorithm also rejects an algorithm still validating, independent of any reference
    # (ValidationException "Cannot delete Algorithm in InProgress status") -- wait this one to
    # Completed too so the later delete tests only the "unreferenced" comparison, not this
    # unrelated transient state.
    unreferenced_status = _poll_until(
        lambda: sm.describe_algorithm(AlgorithmName=algo_unreferenced)["AlgorithmStatus"],
        lambda s: s in ("Completed", "Failed"),
        timeout_s=120,
        interval_s=3,
    )
    assert unreferenced_status == "Completed", (
        f"expected {algo_unreferenced!r} to validate Completed, got {unreferenced_status!r}"
    )

    job_name = ctx.unique_name("sim2real-behav-tj-")
    _retry_role_propagation(
        lambda: sm.create_training_job(
            TrainingJobName=job_name,
            AlgorithmSpecification={"AlgorithmName": algo_referenced, "TrainingInputMode": "File"},
            RoleArn=role_arn,
            OutputDataConfig={"S3OutputPath": f"s3://sim2real-behav/{job_name}/output"},
            ResourceConfig={"InstanceType": "ml.m5.large", "InstanceCount": 1, "VolumeSizeInGB": 10},
            StoppingCondition={"MaxRuntimeInSeconds": 120},
            Tags=[{"Key": "sim2real", "Value": "1"}],
        )
    )
    ctx.on_cleanup(lambda: _best_effort(lambda: sm.stop_training_job(TrainingJobName=job_name), terminal_ok=True))

    # The reference must actually be live (job not yet terminal) before it can block
    # anything -- confirm the premise rather than assuming it.
    job_status = sm.describe_training_job(TrainingJobName=job_name)["TrainingJobStatus"]
    assert job_status in ("InProgress", "Starting"), (
        f"expected the training job to be live (not yet terminal) when testing the "
        f"conflict, got {job_status!r}"
    )

    # Real AWS does not treat a live training job's reference as delete-blocking:
    # DeleteAlgorithm succeeds with no error at all.
    sm.delete_algorithm(AlgorithmName=algo_referenced)

    # Effect present, via an independent read: the algorithm is gone from lookups.
    gone_code, gone_message = _describe_refusal(sm, algo_referenced, timeout_s=60, interval_s=2)
    assert gone_code == "ValidationException", (
        f"expected the deleted algorithm to 404 as ValidationException, got {gone_code!r}"
    )
    expected = f"Algorithm {algo_referenced_arn} does not exist."
    assert gone_message == expected, f"expected {expected!r}, got {gone_message!r}"

    # The training job that referenced it is untouched: still describable, still
    # naming the deleted algorithm in its own AlgorithmSpecification.
    job_described = sm.describe_training_job(TrainingJobName=job_name)
    assert job_described["TrainingJobName"] == job_name, (
        f"expected the training job to remain describable, got {job_described.get('TrainingJobName')!r}"
    )
    # DescribeTrainingJob echoes back the algorithm's ARN here, not the bare name we
    # passed to CreateTrainingJob.
    assert job_described["AlgorithmSpecification"]["AlgorithmName"] == algo_referenced_arn, (
        "expected the training job's own AlgorithmSpecification to still name the "
        f"deleted algorithm's ARN, got {job_described['AlgorithmSpecification'].get('AlgorithmName')!r}"
    )

    # Same-call comparison: an unreferenced sibling algorithm deletes identically,
    # showing the referenced algorithm's delete was not somehow special-cased.
    sm.delete_algorithm(AlgorithmName=algo_unreferenced)
    not_found_code, not_found_message = _describe_refusal(sm, algo_unreferenced, timeout_s=0, interval_s=2)
    assert not_found_code == "ValidationException", f"expected ValidationException, got {not_found_code!r}"
    expected = f"Algorithm {algo_unreferenced_arn} does not exist."
    assert not_found_message == expected, f"expected {expected!r}, got {not_found_message!r}"


# ===== helpers =====

# AWS's built-in XGBoost algorithm image lives in a different, AWS-owned ECR
# registry account per region (there is no single cross-region alias), so this table
# is inherent to using a real pullable image rather than a region pin of convenience.
_XGBOOST_REGISTRY_BY_REGION = {
    "us-east-1": "683313688378",
    "us-east-2": "257758044811",
    "us-west-1": "746614075791",
    "us-west-2": "246618743249",
    "eu-west-1": "685385470294",
    "eu-central-1": "813361260812",
    "ap-southeast-1": "121021644041",
    "ap-southeast-2": "783357654285",
    "ap-northeast-1": "501404015308",
    "ap-south-1": "720646828776",
}


def _xgboost_training_image(region):
    registry_id = _XGBOOST_REGISTRY_BY_REGION.get(region)
    if registry_id is None:
        raise AssertionError(f"no known built-in XGBoost algorithm registry ID for region {region!r}")
    return f"{registry_id}.dkr.ecr.{region}.amazonaws.com/sagemaker-xgboost:1.7-1"


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"timed out waiting for predicate, last value {value!r}")
        time.sleep(interval_s)
        value = probe()
    return value


def _best_effort(fn, *, terminal_ok: bool = False, timeout_s: float = 120.0):
    """Run a teardown call: retry while the algorithm is still InProgress, return once the
    resource is gone (or, with terminal_ok, already terminal), raise everything else."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as exc:
            error = exc.response["Error"]
            message = error.get("Message", "")
            if error["Code"] != "ValidationException":
                raise
            if terminal_ok or "does not exist" in message:
                return
            if "InProgress" not in message or time.monotonic() >= deadline:
                raise
        time.sleep(2)


def _describe_refusal(sm, name, *, timeout_s: float, interval_s: float):
    """Poll DescribeAlgorithm until it refuses and return the refusal's (code, message); a describe
    that still succeeds at the deadline raises."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            described = sm.describe_algorithm(AlgorithmName=name)
        except ClientError as exc:
            return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        if time.monotonic() >= deadline:
            raise AssertionError(f"expected {name!r} to be gone, but it still describes: {described!r}")
        time.sleep(interval_s)


def _ensure_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {"Effect": "Allow", "Principal": {"Service": "sagemaker.amazonaws.com"}, "Action": "sts:AssumeRole"}
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "1"}],
    )
    role_arn = role["Role"]["Arn"]
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)

    def _cleanup():
        try:
            iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchEntity":
                raise
        iam.delete_role(RoleName=role_name)

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_role_propagation(fn, timeout_s: float = 60.0, interval_s: float = 5.0):
    """A role just created by _ensure_execution_role is not yet assumable by
    SageMaker everywhere; retry the caller's dependent call until propagation lands
    rather than guessing a fixed sleep."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as exc:
            last_exc = exc
            code = exc.response.get("Error", {}).get("Code", "")
            if code in ("AccessDeniedException", "ValidationException"):
                time.sleep(interval_s)
                continue
            raise
    raise last_exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
