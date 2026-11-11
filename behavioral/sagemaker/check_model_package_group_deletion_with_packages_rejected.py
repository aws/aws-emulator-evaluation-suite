"""model-package-group-deletion-with-packages-rejected."""
from __future__ import annotations

import base64
import subprocess
from urllib.parse import urlsplit

from botocore.exceptions import ClientError

from behavioral_harness import tags
from fidelity_tests_runner import RequiredToolMissing, require_tools

CHECK = "model-package-group-deletion-with-packages-rejected"
GROUP = "data-plane"
SERVICES = ["sagemaker"]

PUBLIC_IMAGE = "public.ecr.aws/docker/library/busybox:latest"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:native", "plane:control", "plane:data")
def run(ctx) -> None:
    """DeleteModelPackageGroup on a group still holding a model package fails ValidationException
    and the group survives; after the package is deleted the same call succeeds, and the group
    then reads and re-deletes as "does not exist"."""
    require_tools("docker")

    sm = ctx.client("sagemaker")
    s3 = ctx.client("s3")
    ecr = ctx.client("ecr")

    resource_tags = [{"Key": "sim2real:managed", "Value": "true"}]

    group_name = ctx.unique_name("sim2real-mpg-")
    group_arn = sm.create_model_package_group(ModelPackageGroupName=group_name, Tags=resource_tags)["ModelPackageGroupArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name)))
    # CreateModelPackageGroup auto-creates a SageMaker Lineage "Context" tracking entity for the
    # group; DeleteModelPackageGroup does NOT cascade-delete it, so it must be cleaned up separately.
    ctx.on_cleanup(lambda: _delete_lineage_context(sm, group_arn))

    bucket = _create_bucket(ctx, s3, resource_tags)
    s3.put_object(Bucket=bucket, Key="model.tar.gz", Body=b"sim2real-fake-model-artifact")

    # CreateModelPackage validates the container image is pullable ("Cannot find the requested
    # image" for an empty repo), so push a real one.
    image = _push_image(ctx, ecr)

    data_url = f"s3://{bucket}/model.tar.gz"
    pkg_arn = sm.create_model_package(
        ModelPackageGroupName=group_name,
        InferenceSpecification={
            "Containers": [{"Image": image, "ModelDataUrl": data_url}],
            "SupportedContentTypes": ["text/csv"],
            "SupportedResponseMIMETypes": ["text/csv"],
        },
    )["ModelPackageArn"]
    ctx.on_cleanup(lambda: _best_effort(lambda: sm.delete_model_package(ModelPackageName=pkg_arn)))

    code, message = _error(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))
    assert code == "ValidationException", f"expected ValidationException deleting a non-empty group, got {code!r}"
    expected_message = (
        f"Model Package Group {group_arn} cannot be deleted because it still contains "
        "Model Packages."
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    still_there = sm.describe_model_package_group(ModelPackageGroupName=group_name)
    assert still_there["ModelPackageGroupName"] == group_name, (
        f"expected the group {group_name!r} to survive the rejected delete, "
        f"got {still_there['ModelPackageGroupName']!r}"
    )

    sm.delete_model_package(ModelPackageName=pkg_arn)
    sm.delete_model_package_group(ModelPackageGroupName=group_name)

    final_code, final_message = _error(lambda: sm.describe_model_package_group(ModelPackageGroupName=group_name))
    assert final_code == "ValidationException", f"expected the group to be gone, got {final_code!r}"
    expected_message = f"ModelPackageGroup {group_arn} does not exist."
    assert final_message == expected_message, (
        f"expected message {expected_message!r}, got {final_message!r}"
    )

    delete_again_code, delete_again_message = _error(lambda: sm.delete_model_package_group(ModelPackageGroupName=group_name))
    assert delete_again_code == final_code, f"expected repeat delete on the dead group to fail the same way, got {delete_again_code!r}"
    expected_message = f"ModelPackageGroup {group_arn} does not exist."
    assert delete_again_message == expected_message, (
        f"expected message {expected_message!r}, got {delete_again_message!r}"
    )


def _error(fn):
    """Call fn(); return the (code, message) of its ClientError. An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _best_effort(fn):
    try:
        fn()
    except Exception:
        pass


def _delete_lineage_context(sm, group_arn: str) -> None:
    for summary in sm.list_contexts(SourceUri=group_arn).get("ContextSummaries", []):
        _best_effort(lambda name=summary["ContextName"]: sm.delete_context(ContextName=name))


def _create_bucket(ctx, s3, resource_tags):
    bucket = ctx.unique_name("sim2real-mpg-").lower().replace("_", "-")
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    s3.put_bucket_tagging(Bucket=bucket, Tagging={"TagSet": resource_tags})

    def _cleanup():
        paginator = s3.get_paginator("list_objects_v2")
        for page in paginator.paginate(Bucket=bucket):
            for obj in page.get("Contents", []):
                _best_effort(lambda k=obj["Key"]: s3.delete_object(Bucket=bucket, Key=k))
        _best_effort(lambda: s3.delete_bucket(Bucket=bucket))

    ctx.on_cleanup(_cleanup)
    return bucket


def _push_image(ctx, ecr) -> str:
    """Push the locally pre-seeded image into a new private ECR repo; return its repositoryUri tag.

    Docker reaches the registry at the host named by the proxyEndpoint, via ctx.endpoint_url."""
    repo_name = ctx.unique_name("sim2real-mpg-").lower()
    repo = ecr.create_repository(
        repositoryName=repo_name,
        tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["repository"]
    ctx.on_cleanup(lambda: _best_effort(lambda: ecr.delete_repository(repositoryName=repo_name, force=True)))

    repo_uri = repo["repositoryUri"]
    image_ref = f"{repo_uri}:v1"
    seeded = _run_shell(ctx, ["docker", "image", "inspect", PUBLIC_IMAGE], check=False)
    if seeded.returncode != 0:
        raise RequiredToolMissing([f"docker image {PUBLIC_IMAGE} (pre-seed it on the runner)"])
    auth = ecr.get_authorization_token()["authorizationData"][0]
    user, password = base64.b64decode(auth["authorizationToken"]).decode().split(":", 1)
    registry = urlsplit(ctx.endpoint_url(auth["proxyEndpoint"])).netloc
    target = f"{registry}/{repo_uri.split('/', 1)[1]}:v1"
    _run_shell(ctx, ["docker", "login", "--username", user, "--password-stdin", registry],
               stdin=password, timeout_s=120)
    _run_shell(ctx, ["docker", "tag", PUBLIC_IMAGE, target])
    _run_shell(ctx, ["docker", "push", target], timeout_s=300)
    return image_ref


def _run_shell(ctx, command, *, timeout_s=60.0, check=True, stdin=None):
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    result = subprocess.run(
        command,
        shell=isinstance(command, str),
        input=stdin,
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout_s,
    )
    if check and result.returncode != 0:
        raise AssertionError(
            f"Command failed (rc={result.returncode}):\n  cmd: {command}\n"
            f"  stderr: {result.stderr[-500:]}"
        )
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
