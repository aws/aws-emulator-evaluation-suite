"""create-image-full-build-lifecycle."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-image-full-build-lifecycle"
GROUP = "data-plane"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c3", "cap:c4", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """CreateImage drives a real image build through PENDING/BUILDING to AVAILABLE and yields a usable output AMI."""
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
        tags={"sim2real-check": CHECK},
    )["imageBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_image(imageBuildVersionArn=image_arn))
    ctx.on_cleanup(lambda: _deregister_output_amis(ctx, ib, image_arn))

    status = _poll_until_terminal(ib, image_arn, timeout_s=2700)
    assert status == "AVAILABLE", f"image build ended in unexpected terminal state {status}"

    image = ib.get_image(imageBuildVersionArn=image_arn)["image"]
    amis = image.get("outputResources", {}).get("amis", [])
    assert len(amis) >= 1, f"expected at least one output AMI, got {amis!r}"
    ami_id = amis[0]["image"]
    assert ami_id.startswith("ami-"), f"unexpected AMI id format: {ami_id!r}"

    # ImageBuilder's own GetImage is a self-report; the destination that actually decides
    # whether the AMI is a usable image is EC2's registry.
    ec2 = ctx.client("ec2")
    described = ec2.describe_images(ImageIds=[ami_id])["Images"]
    assert len(described) == 1, f"AMI {ami_id} not visible via ec2:DescribeImages: {described!r}"
    assert described[0]["State"] == "available", (
        f"AMI {ami_id} is {described[0]['State']!r} in EC2's own registry, not available"
    )


# ===== helpers =====
def _create_instance_profile(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ib-profile-")
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(
        RoleName=name,
        AssumeRolePolicyDocument=trust,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    for policy_arn in (
        "arn:aws:iam::aws:policy/EC2InstanceProfileForImageBuilder",
        "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore",
    ):
        iam.attach_role_policy(RoleName=name, PolicyArn=policy_arn)
        ctx.on_cleanup(lambda p=policy_arn: iam.detach_role_policy(RoleName=name, PolicyArn=p))
    iam.create_instance_profile(
        InstanceProfileName=name,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
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
                name=name,
                instanceProfileName=profile_name,
                clientToken=str(uuid.uuid4()),
                tags={"sim2real-check": CHECK},
            )["infrastructureConfigurationArn"]
        except ClientError as exc:
            # IAM instance profiles are eventually consistent to other services: ImageBuilder can
            # answer "does not exist" for several seconds after AddRoleToInstanceProfile returned,
            # reported as InvalidParameterValueException or InvalidRequestException.
            code = exc.response["Error"]["Code"]
            if code not in ("InvalidRequestException", "InvalidParameterValueException"):
                raise
            last_exc = exc
            time.sleep(2)
    raise last_exc


def _create_image_recipe(ctx, ib):
    parent_image = f"arn:aws:imagebuilder:{ctx.region}:aws:image/amazon-linux-2-x86/x.x.x"
    return ib.create_image_recipe(
        name=ctx.unique_name("sim2real-recipe-"),
        semanticVersion="1.0.0",
        parentImage=parent_image,
        clientToken=str(uuid.uuid4()),
        tags={"sim2real-check": CHECK},
    )["imageRecipeArn"]


def _poll_until_terminal(ib, image_arn, timeout_s):
    terminal = {"AVAILABLE", "FAILED", "CANCELLED", "DEPRECATED", "DELETED", "DISABLED"}
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
