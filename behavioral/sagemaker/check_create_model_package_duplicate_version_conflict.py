"""create-model-package-duplicate-version-conflict."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "create-model-package-duplicate-version-conflict"
GROUP = "concurrency"
SERVICES = ["sagemaker"]

_TAGS = [{"Key": "sim2real", "Value": CHECK}]

# SageMaker's built-in-algorithm inference images are pullable by any account, so
# CreateModelPackage's registry-access check succeeds without pushing an image.
_BUILTIN_ALGO_ACCOUNT_BY_REGION = {
    "us-east-1": "382416733822",
    "us-east-2": "404615174143",
    "us-west-1": "632365934929",
    "us-west-2": "174872318107",
    "eu-west-1": "685385470294",
    "eu-central-1": "664544806723",
    "ap-southeast-1": "475088953585",
    "ap-southeast-2": "712309505854",
    "ap-northeast-1": "351501993468",
    "ap-south-1": "991648021394",
    "ca-central-1": "469771592824",
}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateModelPackage calls into one fresh ModelPackageGroup receive unique, dense
    versions 1..N: the version counter is atomic under contention."""
    account = _BUILTIN_ALGO_ACCOUNT_BY_REGION.get(ctx.region)
    if account is None:
        raise AssertionError(
            f"no known built-in-algorithm ECR registry account for region {ctx.region}"
        )
    image = f"{account}.dkr.ecr.{ctx.region}.amazonaws.com/kmeans:1"

    sm = ctx.client("sagemaker")
    bucket, key = _create_model_artifact(ctx)
    group_name = ctx.unique_name("sim2real-mpg-ver-")
    sm.create_model_package_group(ModelPackageGroupName=group_name, Tags=_TAGS)
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    n = 4
    inference_spec = {
        "Containers": [
            {
                "Image": image,
                "ModelDataUrl": f"s3://{bucket}/{key}",
            }
        ],
        "SupportedContentTypes": ["text/csv"],
        "SupportedResponseMIMETypes": ["text/csv"],
        "SupportedRealtimeInferenceInstanceTypes": ["ml.t2.medium"],
        "SupportedTransformInstanceTypes": ["ml.m5.large"],
    }

    def _create(_):
        resp = sm.create_model_package(
            ModelPackageGroupName=group_name, InferenceSpecification=inference_spec
        )
        return resp["ModelPackageArn"]

    with ThreadPoolExecutor(max_workers=n) as pool:
        arns = list(pool.map(_create, range(n)))

    for arn in arns:
        ctx.on_cleanup(lambda a=arn: sm.delete_model_package(ModelPackageName=a))

    versions = [sm.describe_model_package(ModelPackageName=arn)["ModelPackageVersion"] for arn in arns]
    assert len(set(versions)) == n, f"expected {n} unique versions, got {versions}"
    assert set(versions) == set(range(1, n + 1)), (
        f"expected a dense sequential {{1..{n}}} version assignment for a fresh "
        f"group, got {sorted(versions)}"
    )


def _create_model_artifact(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-mp-ver-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(
            Bucket=bucket,
            CreateBucketConfiguration={"LocationConstraint": ctx.region},
        )
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=bucket))
    key = "model.tar.gz"
    s3.put_object(Bucket=bucket, Key=key, Body=b"sim2real-placeholder-model-artifact")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key=key))
    return bucket, key


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

