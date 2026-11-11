"""sagemaker-model-package-s3-artifact-validation."""
from __future__ import annotations

import io
import tarfile
import time
from typing import Any
from urllib.parse import urlparse

from behavioral_harness import tags

CHECK = "sagemaker-model-package-s3-artifact-validation"
GROUP = "data-format"
SERVICES = ["s3", "sagemaker"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx: Any) -> None:
    """A registered ModelPackage reaches Completed as version 1 of its group, and its reported S3
    artifact reference resolves to a real, readable, byte-identical object.
    """
    s3 = ctx.client("s3")
    sm = ctx.client("sagemaker")

    bucket = _create_bucket(ctx)
    key = "packages/model.tar.gz"
    body = _build_model_tarball(b"sim2real-model-package-weights")
    s3.put_object(Bucket=bucket, Key=key, Body=body)
    model_data_url = f"s3://{bucket}/{key}"

    group_name = ctx.unique_name("sim2real-sm-mpg-")
    sm.create_model_package_group(
        ModelPackageGroupName=group_name,
        Tags=[{"Key": "sim2real", "Value": "model-package-s3-artifact-validation"}],
    )
    ctx.on_cleanup(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))

    image = f"{_xgboost_registry_account(ctx.region)}.dkr.ecr.{ctx.region}.amazonaws.com/sagemaker-xgboost:1.7-1"
    resp = sm.create_model_package(
        ModelPackageGroupName=group_name,
        InferenceSpecification={
            "Containers": [{"Image": image, "ModelDataUrl": model_data_url}],
            "SupportedContentTypes": ["text/csv"],
            "SupportedResponseMIMETypes": ["text/csv"],
        },
        ModelApprovalStatus="PendingManualApproval",
        # CreateModelPackage rejects Tags for a versioned package (ValidationException:
        # "Tags are not supported in Model Package versions") -- the group above is the
        # only place a tag search can find this resource family.
    )
    package_arn = resp["ModelPackageArn"]
    ctx.on_cleanup(lambda: sm.delete_model_package(ModelPackageName=package_arn))

    deadline = time.monotonic() + min(300.0, (ctx.time_left() or 300.0) - 5)
    desc = sm.describe_model_package(ModelPackageName=package_arn)
    while desc["ModelPackageStatus"] in ("Pending", "InProgress") and time.monotonic() < deadline:
        time.sleep(5)
        desc = sm.describe_model_package(ModelPackageName=package_arn)
    derived = (
        desc["ModelPackageStatus"],
        desc.get("ModelPackageVersion"),
        desc.get("ModelPackageGroupName"),
        desc.get("ModelApprovalStatus"),
        desc.get("ModelPackageArn"),
    )
    assert derived == ("Completed", 1, group_name, "PendingManualApproval", package_arn), (
        f"expected the first package of {group_name!r} to be Completed version 1, "
        f"PendingManualApproval, at {package_arn!r}; got "
        f"(status, version, group, approval, arn)={derived!r}"
    )
    container = desc["InferenceSpecification"]["Containers"][0]
    assert container["ModelDataUrl"] == model_data_url, f"expected {model_data_url!r}, got {container['ModelDataUrl']!r}"
    assert container["Image"] == image, f"expected {image!r}, got {container['Image']!r}"

    arns = [p["ModelPackageArn"] for p in sm.list_model_packages(ModelPackageGroupName=group_name)["ModelPackageSummaryList"]]
    assert package_arn in arns, f"{package_arn!r} not in {arns!r}"

    # Resolve the S3 location from what DescribeModelPackage actually reported, not from the
    # local variables used to build it -- an independent read of the destination it names.
    parsed = urlparse(container["ModelDataUrl"])
    described_bucket, described_key = parsed.netloc, parsed.path.lstrip("/")
    fetched = s3.get_object(Bucket=described_bucket, Key=described_key)["Body"].read()
    assert fetched == body, "GetObject on the DescribeModelPackage-reported S3 location did not return the registered artifact bytes"


def _build_model_tarball(content: bytes) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        data = io.BytesIO(content)
        info = tarfile.TarInfo(name="model.bin")
        info.size = len(content)
        tar.addfile(info, data)
    return buf.getvalue()


def _xgboost_registry_account(region: str) -> str:
    # Per-region ECR registry account IDs that host the SageMaker-managed
    # "sagemaker-xgboost" framework/algorithm container images.
    accounts = {
        "us-east-1": "683313688378",
        "us-east-2": "257758044811",
        "us-west-1": "746614075791",
        "us-west-2": "246618743249",
        "ca-central-1": "341280168497",
        "eu-west-1": "141502667606",
        "eu-west-2": "764974769150",
        "eu-west-3": "659782779980",
        "eu-central-1": "492215442770",
        "eu-north-1": "669576153137",
        "ap-northeast-1": "354813040037",
        "ap-northeast-2": "366743142698",
        "ap-southeast-1": "121021644041",
        "ap-southeast-2": "783357654285",
        "ap-south-1": "720646828776",
        "sa-east-1": "737474898029",
    }
    return accounts.get(region, "683313688378")


def _create_bucket(ctx: Any) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-sm-s3-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=name)
    else:
        s3.create_bucket(Bucket=name, CreateBucketConfiguration={"LocationConstraint": ctx.region})

    def _cleanup() -> None:
        contents = s3.list_objects_v2(Bucket=name).get("Contents", [])
        if contents:
            s3.delete_objects(Bucket=name, Delete={"Objects": [{"Key": o["Key"]} for o in contents]})
        s3.delete_bucket(Bucket=name)

    ctx.on_cleanup(_cleanup)
    return name


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
