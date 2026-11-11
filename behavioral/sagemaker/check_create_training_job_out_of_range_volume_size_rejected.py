"""create-training-job-out-of-range-volume-size-rejected."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "create-training-job-out-of-range-volume-size-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]

# Registry account IDs for the SageMaker 1P built-in-algorithm ECR images. These images are
# publicly readable cross-account (AWS grants pull access to any customer account), so they
# let CreateTrainingJob validate a real, resolvable image without us owning a private ECR
# repo of our own. A region-mismatched registry/DNS-suffix combination is itself rejected
# with ValidationException, so this must track ctx.region exactly.
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateTrainingJob rejects a VolumeSizeInGB far beyond the EBS limit with ResourceLimitExceeded
    (a quota violation, not a ValidationException) rather than clamping it, while an identical
    request with a valid volume size succeeds (control)."""
    role_arn = _create_sagemaker_role(ctx)
    sm = ctx.client("sagemaker")

    registry_id = _BUILTIN_ALGO_REGISTRY[ctx.region]
    base_params = dict(
        AlgorithmSpecification={
            "TrainingImage": f"{registry_id}.dkr.ecr.{ctx.region}.amazonaws.com/linear-learner:1",
            "TrainingInputMode": "File",
        },
        RoleArn=role_arn,
        OutputDataConfig={"S3OutputPath": f"s3://sim2real-behav-{uuid.uuid4().hex}/out"},
        StoppingCondition={"MaxRuntimeInSeconds": 600},
    )

    bad_name = ctx.unique_name("sim2real-badvol-")
    code, message = _error(
        lambda: _call_with_role_propagation_retry(
            lambda: sm.create_training_job(
                TrainingJobName=bad_name,
                ResourceConfig={
                    "InstanceType": "ml.m5.large",
                    "InstanceCount": 1,
                    "VolumeSizeInGB": 999999999,
                },
                **base_params,
            )
        )
    )
    assert code == "ResourceLimitExceeded", f"expected ResourceLimitExceeded, got {code}"
    assert message == (
        "The account-level service limit 'Size of EBS volume for a training job instance' is "
        "1024 GBs, with total requested utilization of 999999999 GBs. Please use AWS Service "
        "Quotas to request an increase for this quota. If AWS Service Quotas is not available, "
        "contact AWS support to request an increase for this quota."
    ), f"unexpected ResourceLimitExceeded message: {message!r}"

    # (b) effect absent: the rejected job was never created. DescribeTrainingJob's
    # model declares ResourceNotFound, but real SageMaker answers a missing training
    # job with ValidationException (its own waiters.json failure matcher agrees).
    absent_code, absent_message = _error(lambda: sm.describe_training_job(TrainingJobName=bad_name))
    assert absent_code == "ValidationException", f"expected ValidationException, got {absent_code}"
    assert absent_message == "Requested resource not found.", (
        f"unexpected not-found message: {absent_message!r}"
    )

    # (c) positive control: identical shape with a valid volume size succeeds.
    good_name = ctx.unique_name("sim2real-goodvol-")

    def _stop_good():
        from botocore.exceptions import ClientError

        try:
            sm.stop_training_job(TrainingJobName=good_name)
        except ClientError as exc:
            # ValidationException: the job is terminal or was never created.
            if exc.response["Error"]["Code"] != "ValidationException":
                raise

    ctx.on_cleanup(_stop_good)
    _call_with_role_propagation_retry(
        lambda: sm.create_training_job(
            TrainingJobName=good_name,
            ResourceConfig={
                "InstanceType": "ml.m5.large",
                "InstanceCount": 1,
                "VolumeSizeInGB": 30,
            },
            **base_params,
        )
    )
    described = sm.describe_training_job(TrainingJobName=good_name)
    assert described["TrainingJobName"] == good_name, (
        f"expected the control job {good_name!r} to describe back its own name, "
        f"got {described.get('TrainingJobName')!r}"
    )
    # Immediately stop to avoid burning real training compute time/cost.
    sm.stop_training_job(TrainingJobName=good_name)


# ===== helpers =====

def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so a target that
    accepts what AWS refuses never reads as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _create_sagemaker_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-smrole-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "sagemaker.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    role = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Role"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn))
    return role["Arn"]


def _is_role_not_ready(err) -> bool:
    code = err.response["Error"]["Code"]
    message = err.response["Error"].get("Message", "")
    if code == "AccessDeniedException":
        return True
    # SageMaker also reports a not-yet-propagated role as ValidationException with an
    # "assume role" message, which is indistinguishable by code alone from the
    # out-of-range-volume ValidationException this check exists to detect.
    return code == "ValidationException" and "assume role" in message.lower()


def _call_with_role_propagation_retry(fn, timeout_s=60.0):
    """IAM trust/attachment propagation is eventually consistent, and there is nothing
    observable to poll before SageMaker can assume a just-created role. Retry only the
    role-not-ready errors that propagation delay produces, bounded by a deadline; let
    every other error — including the out-of-range-volume error under test — surface
    as-is."""
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + timeout_s
    last_err = None
    while time.monotonic() < deadline:
        try:
            return fn()
        except ClientError as err:
            if _is_role_not_ready(err):
                last_err = err
                time.sleep(3)
                continue
            raise
    raise last_err


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
