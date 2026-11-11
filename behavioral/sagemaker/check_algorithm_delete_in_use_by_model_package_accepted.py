"""algorithm-delete-in-use-by-model-package-accepted."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "algorithm-delete-in-use-by-model-package-accepted"
GROUP = "state-machine"
SERVICES = ["sagemaker"]

_TAGS = [{"Key": "sim2real-behav-check", "Value": CHECK}]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAlgorithm succeeds while a ModelPackage references the algorithm: Describe and a second
    delete then raise ValidationException "does not exist", and the ModelPackage still describes
    with the algorithm in its SourceAlgorithmSpecification."""
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    algo_name = ctx.unique_name("sim2real-algo-inuse-")
    pkg_name = ctx.unique_name("sim2real-modelpkg-inuse-")
    bucket = ctx.unique_name("sim2real-algo-mp-").lower().replace("_", "-")

    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": _TAGS})
    ctx.on_cleanup(lambda: _safe_call(lambda: s3.delete_bucket(Bucket=bucket)))

    training_image = _builtin_algorithm_image(ctx)
    algo_arn = sm.create_algorithm(
        AlgorithmName=algo_name,
        TrainingSpecification=_minimal_training_spec(training_image),
        InferenceSpecification={
            "Containers": [{"Image": training_image}],
            "SupportedContentTypes": ["text/csv"],
            "SupportedResponseMIMETypes": ["text/csv"],
            "SupportedRealtimeInferenceInstanceTypes": ["ml.m5.large"],
            "SupportedTransformInstanceTypes": ["ml.m5.large"],
        },
        Tags=_TAGS,
    )["AlgorithmArn"]
    ctx.on_cleanup(lambda: _safe_call(lambda: sm.delete_algorithm(AlgorithmName=algo_name)))

    _poll_until(
        lambda: sm.describe_algorithm(AlgorithmName=algo_name)["AlgorithmStatus"],
        lambda s: s in ("Completed", "Failed"),
        timeout_s=120.0,
        interval_s=3.0,
    )

    sm.create_model_package(
        ModelPackageName=pkg_name,
        SourceAlgorithmSpecification={
            "SourceAlgorithms": [
                {
                    "AlgorithmName": algo_name,
                    "ModelDataUrl": f"s3://{bucket}/{pkg_name}/model.tar.gz",
                }
            ]
        },
        Tags=_TAGS,
    )
    ctx.on_cleanup(lambda: _safe_call(lambda: sm.delete_model_package(ModelPackageName=pkg_name)))

    # the algorithm is live-referenced right now, yet DeleteAlgorithm still succeeds --
    # the ModelPackage's SourceAlgorithmSpecification is not a delete-blocking dependency.
    sm.delete_algorithm(AlgorithmName=algo_name)

    # independent read at the destination: the algorithm is gone. SageMaker surfaces a
    # deleted algorithm as ValidationException naming it nonexistent, not the generic
    # ResourceNotFound used elsewhere in the API.
    gone_err = _client_error(lambda: sm.describe_algorithm(AlgorithmName=algo_name))
    assert gone_err["Code"] == "ValidationException", (
        f"expected ValidationException naming a nonexistent algorithm, got {gone_err!r}"
    )
    expected_gone = f"Algorithm {algo_arn} does not exist."
    assert gone_err["Message"] == expected_gone, (
        f"expected message {expected_gone!r}, got {gone_err.get('Message')!r}"
    )

    # a mutation on the now-dead id fails with the same specific code, not another
    # silent success -- rules out a stub that always answers "deleted" regardless of state
    redelete_err = _client_error(lambda: sm.delete_algorithm(AlgorithmName=algo_name))
    assert redelete_err["Code"] == "ValidationException", (
        f"expected re-deleting an already-deleted algorithm to report ValidationException naming "
        f"a nonexistent algorithm, got {redelete_err!r}"
    )
    expected_redelete = f"Algorithm {algo_arn} does not exist."
    assert redelete_err["Message"] == expected_redelete, (
        f"expected message {expected_redelete!r}, got {redelete_err.get('Message')!r}"
    )

    # consequence: the referencing model package is untouched by its algorithm's disappearance
    pkg_described = sm.describe_model_package(ModelPackageName=pkg_name)
    assert pkg_described["ModelPackageName"] == pkg_name, (
        f"expected the referencing model package to still describe cleanly, got {pkg_described!r}"
    )
    assert (
        pkg_described["SourceAlgorithmSpecification"]["SourceAlgorithms"][0]["AlgorithmName"]
        == algo_name
    ), "the model package's stored SourceAlgorithmSpecification changed after its algorithm was deleted"


# ===== helpers =====
# SageMaker's own built-in XGBoost ECR image is publicly pullable by any account, so
# referencing it (instead of a made-up image URI in a fake account) lets CreateAlgorithm's
# registry-access check succeed without pushing a real image. Account IDs are the
# well-known "1P algorithms" registry per Region.
_BUILTIN_ALGO_ACCOUNT_BY_REGION = {
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


def _builtin_algorithm_image(ctx) -> str:
    account = _BUILTIN_ALGO_ACCOUNT_BY_REGION.get(ctx.region)
    if account is None:
        raise AssertionError(f"no known built-in-algorithm ECR registry account for region {ctx.region!r}")
    return f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-xgboost:1.7-1"


def _minimal_training_spec(training_image: str) -> dict:
    return {
        "TrainingImage": training_image,
        "SupportedTrainingInstanceTypes": ["ml.m5.large"],
        "TrainingChannels": [
            {
                "Name": "training",
                "SupportedContentTypes": ["text/csv"],
                "SupportedInputModes": ["File"],
            }
        ],
    }


def _safe_call(fn) -> None:
    """Run a teardown delete; return only when the resource is already gone, raise the rest."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as e:
        err = e.response["Error"]
        if err.get("Code") == "NoSuchBucket":
            return
        if err.get("Code") != "ValidationException" or "does not exist" not in err.get("Message", ""):
            raise


def _client_error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    value = None
    while time.monotonic() < deadline:
        value = probe()
        if predicate(value):
            return value
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
