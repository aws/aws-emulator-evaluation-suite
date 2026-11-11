"""algorithm-delete-while-referenced-by-model-package-succeeds."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "algorithm-delete-while-referenced-by-model-package-succeeds"
GROUP = "state-machine"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeleteAlgorithm succeeds while a ModelPackage references the algorithm: the algorithm
    disappears from lookups, while the ModelPackage still describes and names the deleted
    algorithm in its SourceAlgorithmSpecification."""
    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    algo_name = ctx.unique_name("sim2real-algo-referenced-")

    # CreateAlgorithm validates that the TrainingImage resolves to a pullable image; AWS's built-in
    # XGBoost algorithm image is pullable by any account in these regions.
    xgboost_registry_by_region = {
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
    registry_id = xgboost_registry_by_region.get(ctx.region)
    if registry_id is None:

        raise AssertionError(f"no known built-in XGBoost algorithm registry ID for region {ctx.region!r}")
    training_image = f"{registry_id}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-xgboost:1.7-1"

    bucket_name = ctx.unique_name("sim2real-algo-mp-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket_name)
    else:
        s3.create_bucket(Bucket=bucket_name, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: s3.delete_bucket(Bucket=bucket_name)))
    s3.put_bucket_tagging(Bucket=bucket_name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})

    training_spec = {
        "TrainingImage": training_image,
        "SupportedTrainingInstanceTypes": ["ml.m5.large"],
        "TrainingChannels": [
            {"Name": "training", "SupportedContentTypes": ["text/csv"], "SupportedInputModes": ["File"]}
        ],
    }
    algo_arn = sm.create_algorithm(
        AlgorithmName=algo_name,
        TrainingSpecification=training_spec,
        InferenceSpecification={
            "Containers": [{"Image": training_image}],
            "SupportedContentTypes": ["text/csv"],
            "SupportedResponseMIMETypes": ["text/csv"],
            "SupportedRealtimeInferenceInstanceTypes": ["ml.m5.large"],
            "SupportedTransformInstanceTypes": ["ml.m5.large"],
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["AlgorithmArn"]
    ctx.on_cleanup(lambda: _ignore_not_found(lambda: sm.delete_algorithm(AlgorithmName=algo_name)))

    algo_status = _poll_until(
        lambda: sm.describe_algorithm(AlgorithmName=algo_name)["AlgorithmStatus"],
        lambda s: s in ("Completed", "Failed"),
        timeout_s=120,
        interval_s=3,
    )
    assert algo_status == "Completed", (
        f"expected the algorithm to validate to Completed (no ValidationSpecification "
        f"failure path exercised here), got {algo_status}"
    )

    model_package_name = ctx.unique_name("sim2real-mp-")
    sm.create_model_package(
        ModelPackageName=model_package_name,
        SourceAlgorithmSpecification={
            "SourceAlgorithms": [
                {
                    "AlgorithmName": algo_name,
                    "ModelDataUrl": f"s3://{bucket_name}/{algo_name}/model.tar.gz",
                }
            ]
        },
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(
        lambda: _ignore_not_found(lambda: sm.delete_model_package(ModelPackageName=model_package_name))
    )
    mp_status = _poll_until(
        lambda: sm.describe_model_package(ModelPackageName=model_package_name)["ModelPackageStatus"],
        lambda s: s in ("Completed", "Failed"),
        timeout_s=120,
        interval_s=3,
    )
    assert mp_status == "Completed", (
        f"expected the model package to validate to Completed (no ValidationSpecification "
        f"supplied), got {mp_status}"
    )

    sm.delete_algorithm(AlgorithmName=algo_name)

    # Effect present: the algorithm is gone from lookups after the (unblocked) delete.
    gone = _poll_until(
        lambda: _describe_algorithm_or_error(sm, algo_name),
        lambda r: "Code" in r,
        timeout_s=60,
        interval_s=3,
    )
    expected = f"Algorithm {algo_arn} does not exist."
    assert gone["Code"] == "ValidationException" and gone.get("Message") == expected, (
        f"expected the deleted algorithm to fail as ValidationException {expected!r}, got {gone!r}"
    )

    # The ModelPackage that referenced it is untouched: still describable, still
    # naming the (now-deleted) algorithm in its stored SourceAlgorithmSpecification.
    mp_described = sm.describe_model_package(ModelPackageName=model_package_name)
    assert mp_described["ModelPackageName"] == model_package_name, (
        f"expected the referencing model package {model_package_name!r} to still be "
        f"describable, got {mp_described.get('ModelPackageName')!r}"
    )
    referenced_algo = mp_described["SourceAlgorithmSpecification"]["SourceAlgorithms"][0]["AlgorithmName"]
    assert referenced_algo == algo_name, (
        f"expected the model package to still name the deleted algorithm {algo_name!r} in "
        f"its stored SourceAlgorithmSpecification, got {referenced_algo!r}"
    )


# ===== helpers =====
def _describe_algorithm_or_error(sm, name):
    try:
        return sm.describe_algorithm(AlgorithmName=name)
    except ClientError as e:
        return e.response["Error"]


def _ignore_not_found(fn):
    try:
        fn()
    except ClientError as e:
        error = e.response["Error"]
        if error.get("Code") == "NoSuchBucket":
            return
        if error.get("Code") != "ValidationException" or "does not exist" not in error.get("Message", ""):
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float):
    deadline = time.monotonic() + timeout_s
    value = probe()
    while not predicate(value):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s (last value: {value!r})")
        time.sleep(interval_s)
        value = probe()
    return value


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
