"""activating-a-failed-image-version-still-rejects-run."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "activating-a-failed-image-version-still-rejects-run"
GROUP = "image-version-status"
SERVICES = ["lambda-microvms"]


@tags("axis:rejection", "cap:c3", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Activating a FAILED image version is accepted (status ACTIVE, state FAILED, image UPDATED),
    yet RunMicrovm refuses it with ResourceNotFoundException because no build backs it.
    """
    mvm = ctx.client("lambda-microvms")
    base = _managed_base_image(mvm)
    name = ctx.unique_name("sim2real-behav-mvm-")

    created = _create_image_once_role_is_visible(mvm,
        name=name,
        baseImageArn=base,
        buildRoleArn=_create_build_role(ctx),
        codeArtifact={"uri": f"s3://{name}-absent/code.zip"},
        tags={"sim2real-check": CHECK},
    )
    image_arn = created["imageArn"]
    ctx.on_cleanup(lambda: _delete_image(mvm, image_arn))
    version = created["imageVersion"]

    failed = _await_image_state(mvm, image_arn, {"CREATED", "CREATE_FAILED"}, 240)
    assert failed["state"] == "CREATE_FAILED", (
        f"image settled in {failed['state']!r}; this check needs a FAILED version"
    )

    # POSITIVE CONTROL: the service accepts the activation of a version whose build failed.
    activated = mvm.update_microvm_image_version(
        imageIdentifier=image_arn, imageVersion=version, status="ACTIVE"
    )
    assert activated["status"] == "ACTIVE", (
        f"UpdateMicrovmImageVersion returned status {activated['status']!r}, expected ACTIVE"
    )
    assert activated["state"] == "FAILED", (
        f"activation changed the version state to {activated['state']!r}; status and state are "
        f"independent and the build outcome must not be rewritten"
    )

    after = mvm.get_microvm_image(imageIdentifier=image_arn)
    assert after.get("latestActiveImageVersion") == version, (
        f"image reports latestActiveImageVersion {after.get('latestActiveImageVersion')!r} "
        f"after activating {version!r}"
    )
    assert after["state"] == "UPDATED", (
        f"image state is {after['state']!r} after a version status change, expected UPDATED"
    )

    # THE REJECTION: an ACTIVE-but-unbuilt version cannot back a microvm.
    code, message = _error(lambda: mvm.run_microvm(imageIdentifier=image_arn))
    assert code == "ResourceNotFoundException", (
        f"RunMicrovm on an ACTIVE version with no successful build answered {code!r}, expected "
        f"ResourceNotFoundException"
    )
    expected_message = f"No image build found for MicroVM image {image_arn} and version {version}"
    assert message == expected_message, (
        f"RunMicrovm on an ACTIVE version with no successful build answered message "
        f"{message!r}, expected {expected_message!r}"
    )

    # EFFECT ABSENT: no microvm was created for this image.
    running = _all_microvms(mvm, imageIdentifier=image_arn)
    assert running == [], (
        f"RunMicrovm was refused yet ListMicrovms scoped to the image returns "
        f"{[m['microvmId'] for m in running]!r}"
    )


def _account(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


def _error(fn) -> tuple[str, str]:
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call unexpectedly SUCCEEDED where real AWS rejects it")


def _managed_base_image(mvm) -> str:
    arns: list[str] = []
    token = None
    while True:
        page = mvm.list_managed_microvm_images(**({"nextToken": token} if token else {}))
        items = page["items"]
        arns.extend(i["imageArn"] for i in items)
        token = page.get("nextToken")
        if not token or not items:
            break
    assert arns, "ListManagedMicrovmImages returned no managed base image to build from"
    return sorted(arns)[0]


def _all_customer_images(mvm, **kw) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        page = mvm.list_microvm_images(**kw, **({"nextToken": token} if token else {}))
        items = page["items"]
        out.extend(items)
        token = page.get("nextToken")
        if not token or not items:
            break
    return out


def _all_versions(mvm, image_arn: str) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        page = mvm.list_microvm_image_versions(
            imageIdentifier=image_arn, **({"nextToken": token} if token else {})
        )
        items = page["items"]
        out.extend(items)
        token = page.get("nextToken")
        if not token or not items:
            break
    return out


def _all_microvms(mvm, **kw) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        page = mvm.list_microvms(**kw, **({"nextToken": token} if token else {}))
        items = page["items"]
        out.extend(items)
        token = page.get("nextToken")
        if not token or not items:
            break
    return out


def _await_image_state(mvm, image_arn: str, wanted: set[str], budget: float) -> dict:
    deadline = time.time() + budget
    seen = None
    while time.time() < deadline:
        seen = mvm.get_microvm_image(imageIdentifier=image_arn)
        if seen["state"] in wanted:
            return seen
        time.sleep(5)
    raise AssertionError(
        f"image {image_arn!r} never reached one of {sorted(wanted)!r} within {budget}s; "
        f"last state was {(seen or {}).get('state')!r}"
    )


def _delete_image(mvm, image_arn: str) -> None:
    deadline = time.time() + 150
    while True:
        try:
            mvm.delete_microvm_image(imageIdentifier=image_arn)
            return
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return
            if time.time() >= deadline:
                raise
            time.sleep(5)


_BUILD_ROLE_POLICY = "sim2real-mvm-build"


def _create_build_role(ctx) -> str:
    """Create the image build role this check owns and return its ARN.

    Lambda assumes the role to read the code artifact; the policy grants S3 reads and log writes.
    """
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-mvm-role-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": ["sts:AssumeRole", "sts:TagSession"],
            }
        ],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: _delete_build_role(iam, role_name))
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:GetObjectVersion", "s3:ListBucket"],
                "Resource": ["arn:aws:s3:::sim2real-*", "arn:aws:s3:::sim2real-*/*"],
            },
            {
                "Effect": "Allow",
                "Action": ["logs:CreateLogGroup", "logs:CreateLogStream", "logs:PutLogEvents"],
                "Resource": "arn:aws:logs:*:*:*",
            },
        ],
    }
    iam.put_role_policy(
        RoleName=role_name, PolicyName=_BUILD_ROLE_POLICY, PolicyDocument=json.dumps(policy)
    )
    return role_arn


def _delete_build_role(iam, role_name: str) -> None:
    try:
        iam.delete_role_policy(RoleName=role_name, PolicyName=_BUILD_ROLE_POLICY)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise
    try:
        iam.delete_role(RoleName=role_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _create_image_once_role_is_visible(mvm, budget: float = 90.0, **kwargs) -> dict:
    """CreateMicrovmImage, retried while the freshly created build role propagates."""
    deadline = time.time() + budget
    while True:
        try:
            return mvm.create_microvm_image(**kwargs)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code not in ("AccessDeniedException", "ResourceNotFoundException", "ValidationException"):
                raise
            if "role" not in exc.response["Error"].get("Message", "").lower():
                raise
            if time.time() >= deadline:
                raise
            time.sleep(5)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
