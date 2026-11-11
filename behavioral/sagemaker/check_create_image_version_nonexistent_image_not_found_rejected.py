"""create-image-version-nonexistent-image-not-found-rejected."""
from __future__ import annotations

import json
import time
import uuid

from behavioral_harness import tags

CHECK = "create-image-version-nonexistent-image-not-found-rejected"
GROUP = "error-semantics"
SERVICES = ["sagemaker"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateImageVersion naming a parent ImageName that does not exist is rejected with
    ResourceNotFound and creates nothing, while the same call against a real image succeeds and
    is observable via DescribeImageVersion (the positive control)."""
    sm = ctx.client("sagemaker")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    missing_image_name = ctx.unique_name("sim2real-behav-missing-img-")
    base_image = f"{account_id}.dkr.ecr.{ctx.region}.amazonaws.com/sim2real-behav-nonexistent-repo:latest"
    code, message = _error_code_and_message(
        lambda: sm.create_image_version(
            BaseImage=base_image,
            ClientToken=str(uuid.uuid4()),
            ImageName=missing_image_name,
        )
    )
    expected_message = (
        f"Image with ARN arn:aws:sagemaker:{ctx.region}:{account_id}:image/"
        f"{missing_image_name} does not exist"
    )
    assert code == "ResourceNotFound", f"expected ResourceNotFound, got {code!r} ({message!r})"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: describing the (never-created) parent image also 404s.
    describe_code, describe_message = _error_code_and_message(
        lambda: sm.describe_image(ImageName=missing_image_name)
    )
    assert describe_code == "ResourceNotFound", f"expected ResourceNotFound, got {describe_code!r}"
    assert describe_message == expected_message, (
        f"expected message {expected_message!r}, got {describe_message!r}"
    )

    # Positive control: create a real parent image (with a real IAM execution role -- SageMaker
    # validates that RoleArn can actually be assumed, so a fabricated ARN would fail CreateImage
    # itself rather than exercising the ImageName check) and confirm it settles into CREATED --
    # proving the ImageName in the negative case above genuinely did not exist, rather than every
    # CreateImage/CreateImageVersion call being universally rejected.
    role_arn = _create_execution_role(ctx)
    real_image_name = ctx.unique_name("sim2real-behav-img-")
    ctx.on_cleanup(lambda: _delete_image_if_present(sm, real_image_name))
    settled = _create_image_and_wait_created(sm, real_image_name, role_arn, overall_timeout_s=150)
    assert settled["ImageStatus"] == "CREATED", (
        f"expected CREATED, got {settled.get('ImageStatus')!r} "
        f"(failure_reason={settled.get('FailureReason')!r})"
    )

    # The same call against the real image is accepted.
    ctx.on_cleanup(lambda: _delete_image_version_if_present(sm, real_image_name))
    sm.create_image_version(
        BaseImage=base_image,
        ClientToken=str(uuid.uuid4()),
        ImageName=real_image_name,
    )

    # Terminal read: an independent DescribeImageVersion at the destination proves the version
    # genuinely exists under the real image, rather than trusting the mutating call's own
    # response as the last word.
    described_version = _wait_for_result(
        lambda: sm.describe_image_version(ImageName=real_image_name),
        timeout_s=30,
    )
    assert described_version["ImageArn"] == settled["ImageArn"], (
        f"expected ImageArn {settled['ImageArn']!r}, got {described_version.get('ImageArn')!r}"
    )
    assert described_version["BaseImage"] == base_image, (
        f"expected BaseImage {base_image!r}, got {described_version.get('BaseImage')!r}"
    )



# ===== helpers =====

def _error_code_and_message(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises, so an
    over-permissive target fails as such rather than as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _wait_for_image_settled(sm, image_name, timeout_s=60, interval_s=3):
    deadline = time.time() + timeout_s
    last = None
    while time.time() < deadline:
        last = sm.describe_image(ImageName=image_name)
        if last["ImageStatus"] in ("CREATED", "CREATE_FAILED"):
            return last
        time.sleep(interval_s)
    raise TimeoutError(
        f"image {image_name!r} did not settle within {timeout_s}s (last status: {last!r})"
    )


def _create_image_and_wait_created(sm, image_name, role_arn, overall_timeout_s=150):
    # A just-created IAM role can fail SageMaker's async "assume the role" check for a window
    # after CreateImage returns 200 -- IAM propagation, not a request defect. Retry the whole
    # create-then-settle cycle (deleting the CREATE_FAILED image first) until it clears or the
    # overall deadline passes.
    deadline = time.time() + overall_timeout_s
    last_settled = None
    while time.time() < deadline:
        _retry_role_propagation(lambda: sm.create_image(ImageName=image_name, RoleArn=role_arn))
        remaining = max(5, deadline - time.time())
        last_settled = _wait_for_image_settled(sm, image_name, timeout_s=min(60, remaining))
        if last_settled["ImageStatus"] == "CREATED":
            return last_settled
        reason = (last_settled.get("FailureReason") or "").lower()
        if "assume role" not in reason and "role" not in reason:
            return last_settled
        _delete_image_if_present(sm, image_name)
        time.sleep(5)
    return last_settled


def _wait_for_result(fn, timeout_s=30, interval_s=2):
    deadline = time.time() + timeout_s
    last_exc = None
    while time.time() < deadline:
        try:
            return fn()
        except Exception as exc:  # noqa: BLE001
            last_exc = exc
        time.sleep(interval_s)
    raise last_exc if last_exc is not None else TimeoutError("condition not met within timeout")


def _create_execution_role(ctx):
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-image-role-")
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
    role_arn = iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=trust_policy)["Role"]["Arn"]

    def _cleanup():
        from botocore.exceptions import ClientError

        try:
            iam.delete_role(RoleName=role_name)
        except ClientError as err:
            if err.response["Error"]["Code"] != "NoSuchEntity":
                raise

    ctx.on_cleanup(_cleanup)
    return role_arn


def _retry_role_propagation(fn, timeout_s=60.0, interval_s=5.0):
    from botocore.exceptions import ClientError

    deadline = time.time() + timeout_s
    last_err = None
    while time.time() < deadline:
        try:
            return fn()
        except ClientError as err:
            code = err.response["Error"]["Code"]
            message = err.response["Error"].get("Message", "")
            if code == "ValidationException" and "role" in message.lower():
                last_err = err
                time.sleep(interval_s)
                continue
            raise
    if last_err is not None:
        raise last_err
    raise AssertionError("role propagation retry loop exited without a result")


def _delete_if_present(fn, timeout_s=120.0):
    """Run a delete: retry ResourceInUse while a dependent change settles, return when the
    resource is not found, raise everything else."""
    from botocore.exceptions import ClientError

    deadline = time.time() + timeout_s
    while True:
        try:
            fn()
            return
        except ClientError as err:
            code = err.response["Error"]["Code"]
            if code == "ResourceNotFound":
                return
            if code != "ResourceInUse" or time.time() >= deadline:
                raise
        time.sleep(2)


def _delete_image_if_present(sm, image_name):
    _delete_if_present(lambda: sm.delete_image(ImageName=image_name))


def _delete_image_version_if_present(sm, image_name):
    _delete_if_present(lambda: sm.delete_image_version(ImageName=image_name, Version=1))


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
