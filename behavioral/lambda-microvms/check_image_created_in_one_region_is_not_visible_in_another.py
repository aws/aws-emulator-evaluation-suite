"""image-created-in-one-region-is-not-visible-in-another."""
from __future__ import annotations

import json
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "image-created-in-one-region-is-not-visible-in-another"
GROUP = "region-isolation"
SERVICES = ["lambda-microvms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Images are per-region: the home-region client reads a new image, while a second region's
    client answers ResourceNotFoundException for it and does not list it.
    """
    home = ctx.client("lambda-microvms")
    foreign_region = "us-west-2" if ctx.region != "us-west-2" else "us-east-1"
    foreign = ctx.client("lambda-microvms", region=foreign_region)

    image_arn, _version = _create_image(ctx, home)

    # POSITIVE CONTROL: the home-region client sees what it just created.
    seen = home.get_microvm_image(imageIdentifier=image_arn)
    assert seen["imageArn"] == image_arn, (
        f"home-region GetMicrovmImage returned {seen.get('imageArn')!r}, expected {image_arn!r}"
    )

    code, message = _error(lambda: foreign.get_microvm_image(imageIdentifier=image_arn))
    assert code == "ResourceNotFoundException", (
        f"GetMicrovmImage for a {ctx.region}-created image, queried from {foreign_region!r}, "
        f"answered {code!r}, expected ResourceNotFoundException"
    )
    assert message == f"MicroVMImage not found for MicroVMImageID: {image_arn}", (
        f"GetMicrovmImage from {foreign_region!r} refused the {ctx.region}-created image with "
        f"{message!r}"
    )

    # EFFECT ABSENT: the foreign-region refusal does not list it there either.
    foreign_names = {i["imageArn"] for i in _list_images(foreign)}
    assert image_arn not in foreign_names, (
        f"ListMicrovmImages in {foreign_region!r} includes {image_arn!r}, which was created "
        f"only in {ctx.region!r}"
    )


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


def _create_image(ctx, mvm):
    name = ctx.unique_name("sim2real-behav-mvm-ri-")
    base = _managed_base_image(mvm)
    created = mvm.create_microvm_image(
        name=name,
        baseImageArn=base,
        buildRoleArn=_create_build_role(ctx),
        codeArtifact={"uri": f"s3://{name}-absent/code.zip"},
        tags={"sim2real-origin": "region-isolation"},
    )
    image_arn = created["imageArn"]
    ctx.on_cleanup(lambda: _delete_image(mvm, image_arn))
    return image_arn, created["imageVersion"]


def _list_images(mvm) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        page = mvm.list_microvm_images(**({"nextToken": token} if token else {}))
        items = page["items"]
        out.extend(items)
        token = page.get("nextToken")
        if not token or not items:
            break
    return out


def _create_build_role(ctx) -> str:
    """The image's build role, created by this check and deleted by it."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-mvm-ri-role-")[:64]
    trust = {
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": ["sts:AssumeRole", "sts:TagSession"],
        }],
    }
    role_arn = iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )["Role"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    return role_arn


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises; RAISES if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"]["Message"]
    raise AssertionError("the call unexpectedly SUCCEEDED; real AWS rejects it")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
