"""create-image-version-missing-base-image-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-image-version-missing-base-image-rejected"
GROUP = "overly-permissive"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateImageVersion referencing a nonexistent parent Image is rejected with
    ResourceNotFound and creates no orphan version, while the same call against a real
    Image succeeds."""
    sm = ctx.client("sagemaker")
    role_arn = _create_sagemaker_exec_role(ctx)
    base_image = f"{ctx.account}.dkr.ecr.{ctx.region}.amazonaws.com/sim2real-base:latest"

    # -- negative: ImageName does not exist anywhere in the account
    missing_image_name = ctx.unique_name("sim2real-sm-img-missing-")
    code, message = _error_code_and_message(
        lambda: sm.create_image_version(
            ImageName=missing_image_name,
            BaseImage=base_image,
            ClientToken=str(uuid.uuid4()),
        )
    )
    expected_message = (
        f"Image with ARN arn:aws:sagemaker:{ctx.region}:{ctx.account}:image/"
        f"{missing_image_name} does not exist"
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code} ({message!r})"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: no orphan Image or ImageVersion was created under that name
    not_found_code, not_found_message = _error_code_and_message(
        lambda: sm.describe_image(ImageName=missing_image_name)
    )
    assert not_found_code == "ResourceNotFound", (
        f"expected DescribeImage for a never-created image to fail with "
        f"ResourceNotFound, got {not_found_code}"
    )
    assert not_found_message == expected_message, (
        f"expected message {expected_message!r}, got {not_found_message!r}"
    )

    # -- positive control: same operation against a real, existing Image succeeds
    image_name = ctx.unique_name("sim2real-sm-img-")
    ctx.on_cleanup(lambda: sm.delete_image(ImageName=image_name))
    _create_image_until_ready(sm, image_name, role_arn, timeout_s=90.0)

    resp = sm.create_image_version(
        ImageName=image_name,
        BaseImage=base_image,
        ClientToken=str(uuid.uuid4()),
    )

    def _delete_version():
        try:
            sm.delete_image_version(ImageName=image_name, Version=1)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFound":
                raise

    ctx.on_cleanup(_delete_version)

    described = sm.describe_image_version(ImageName=image_name, Version=1)
    assert described["BaseImage"] == base_image
    assert resp.get("ImageVersionArn") in (None, "None") or "image-version" in resp.get(
        "ImageVersionArn", ""
    )


def _error_code_and_message(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_image_terminal(sm, image_name: str, timeout_s: float):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        desc = sm.describe_image(ImageName=image_name)
        status = desc["ImageStatus"]
        if status in ("CREATED", "CREATE_FAILED"):
            return status, desc.get("FailureReason")
        time.sleep(3)
    raise AssertionError(f"image never reached a terminal state, last={status}")


def _create_image_until_ready(sm, image_name: str, role_arn: str, timeout_s: float) -> None:
    # SageMaker validates that it can assume RoleArn asynchronously, after CreateImage
    # already returned, so a freshly-created role can lose this race even though the
    # call itself succeeded; retry the create once the role has had more time to
    # propagate rather than blocking on a fixed sleep before the first attempt.
    deadline = time.monotonic() + timeout_s
    while True:
        sm.create_image(ImageName=image_name, RoleArn=role_arn)
        status, reason = _wait_image_terminal(sm, image_name, timeout_s=60.0)
        if status == "CREATED":
            return
        if reason and "Unable to assume role" in reason and time.monotonic() < deadline:
            sm.delete_image(ImageName=image_name)
            time.sleep(5)
            continue
        raise AssertionError(f"image creation failed: {status}, reason={reason}")


def _create_sagemaker_exec_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-sm-role-")
    trust_policy = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "sagemaker.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
    )
    role_arn = iam.create_role(
        RoleName=role_name, AssumeRolePolicyDocument=trust_policy
    )["Role"]["Arn"]
    # Cleanups run last-registered-first: the role is deleted only after its policy is detached.
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    policy_arn = "arn:aws:iam::aws:policy/AmazonSageMakerFullAccess"
    iam.attach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    ctx.on_cleanup(
        lambda: iam.detach_role_policy(RoleName=role_name, PolicyArn=policy_arn)
    )
    return role_arn


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
