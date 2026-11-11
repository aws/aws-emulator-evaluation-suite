"""cancel-image-creation-transition."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-image-creation-transition"
GROUP = "state-machine"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CancelImageCreation moves an in-progress build to the CANCELLED terminal state."""
    ib = ctx.client("imagebuilder")
    profile_name = _create_instance_profile(ctx)
    infra_arn = _create_infra_config_with_retry(ctx, ib, ctx.unique_name("sim2real-ib-infra-"), profile_name)
    ctx.on_cleanup(lambda: ib.delete_infrastructure_configuration(infrastructureConfigurationArn=infra_arn))
    recipe_arn = _create_image_recipe(ctx, ib)
    ctx.on_cleanup(lambda: ib.delete_image_recipe(imageRecipeArn=recipe_arn))

    image_arn = ib.create_image(
        infrastructureConfigurationArn=infra_arn,
        imageRecipeArn=recipe_arn,
        imageTestsConfiguration={"imageTestsEnabled": False},
        clientToken=str(uuid.uuid4()),
    )["imageBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_image(imageBuildVersionArn=image_arn))
    ctx.on_cleanup(lambda: _deregister_output_amis(ctx, ib, image_arn))

    ib.cancel_image_creation(imageBuildVersionArn=image_arn, clientToken=str(uuid.uuid4()))

    status = _poll_until_terminal(ib, image_arn, timeout_s=1800)
    assert status == "CANCELLED", f"expected cancel_image_creation to move the build to CANCELLED, got {status!r}"


def _create_instance_profile(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ib-profile-")
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.create_instance_profile(InstanceProfileName=name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=name))
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=name))
    return name


def _create_infra_config_with_retry(ctx, ib, name, profile_name, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return ib.create_infrastructure_configuration(
                name=name, instanceProfileName=profile_name, clientToken=str(uuid.uuid4())
            )["infrastructureConfigurationArn"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("InvalidRequestException", "InvalidParameterValueException"):
                raise
            last_exc = exc
            time.sleep(3)
    raise last_exc


def _create_image_recipe(ctx, ib):
    parent_image = f"arn:aws:imagebuilder:{ctx.region}:aws:image/amazon-linux-2-x86/x.x.x"
    return ib.create_image_recipe(
        name=ctx.unique_name("sim2real-recipe-"),
        semanticVersion="1.0.0",
        parentImage=parent_image,
        clientToken=str(uuid.uuid4()),
    )["imageRecipeArn"]


def _poll_until_terminal(ib, image_arn, timeout_s):
    terminal = {"CANCELLED", "AVAILABLE", "FAILED", "DEPRECATED", "DELETED", "DISABLED"}
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = ib.get_image(imageBuildVersionArn=image_arn)["image"]["state"]["status"]
        if status in terminal:
            return status
        time.sleep(2)
    raise AssertionError(f"image build did not reach a terminal state within {timeout_s}s (last={status})")


def _deregister_output_amis(ctx, ib, image_arn: str) -> None:
    """Deregister a build's output AMIs with their snapshots; deleting the build keeps both."""
    try:
        image = ib.get_image(imageBuildVersionArn=image_arn)["image"]
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
        return
    ec2 = ctx.client("ec2")
    for ami in image.get("outputResources", {}).get("amis", []):
        try:
            ec2.deregister_image(ImageId=ami["image"], DeleteAssociatedSnapshots=True)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") not in ("InvalidAMIID.NotFound", "InvalidAMIID.Unavailable"):
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
