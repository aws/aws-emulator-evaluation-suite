"""image-pipeline-enable-disable-transition."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "image-pipeline-enable-disable-transition"
GROUP = "state-machine"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateImagePipeline toggles status between ENABLED and DISABLED and GetImagePipeline reflects each transition."""
    ib = ctx.client("imagebuilder")
    profile_name = _create_instance_profile(ctx)
    infra_arn = _create_infra_config_with_retry(ctx, ib, ctx.unique_name("sim2real-ib-infra-"), profile_name)
    ctx.on_cleanup(lambda: ib.delete_infrastructure_configuration(infrastructureConfigurationArn=infra_arn))
    recipe_arn = _create_image_recipe(ctx, ib)
    ctx.on_cleanup(lambda: ib.delete_image_recipe(imageRecipeArn=recipe_arn))

    pipeline_arn = ib.create_image_pipeline(
        name=ctx.unique_name("sim2real-pipeline-"),
        infrastructureConfigurationArn=infra_arn,
        imageRecipeArn=recipe_arn,
        status="ENABLED",
        clientToken=str(uuid.uuid4()),
        tags={"sim2real-check": CHECK},
    )["imagePipelineArn"]
    ctx.on_cleanup(lambda: ib.delete_image_pipeline(imagePipelineArn=pipeline_arn))

    status = ib.get_image_pipeline(imagePipelineArn=pipeline_arn)["imagePipeline"]["status"]
    assert status == "ENABLED", f"expected ENABLED after create, got {status!r}"

    ib.update_image_pipeline(
        imagePipelineArn=pipeline_arn,
        infrastructureConfigurationArn=infra_arn,
        imageRecipeArn=recipe_arn,
        status="DISABLED",
        clientToken=str(uuid.uuid4()),
    )
    status = ib.get_image_pipeline(imagePipelineArn=pipeline_arn)["imagePipeline"]["status"]
    assert status == "DISABLED", f"expected DISABLED after update, got {status!r}"

    ib.update_image_pipeline(
        imagePipelineArn=pipeline_arn,
        infrastructureConfigurationArn=infra_arn,
        imageRecipeArn=recipe_arn,
        status="ENABLED",
        clientToken=str(uuid.uuid4()),
    )
    status = ib.get_image_pipeline(imagePipelineArn=pipeline_arn)["imagePipeline"]["status"]
    assert status == "ENABLED", f"expected ENABLED after second update, got {status!r}"


def _create_instance_profile(ctx):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ib-profile-")
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(
        RoleName=name, AssumeRolePolicyDocument=trust, Tags=[{"Key": "sim2real-check", "Value": CHECK}]
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.create_instance_profile(InstanceProfileName=name, Tags=[{"Key": "sim2real-check", "Value": CHECK}])
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
        tags={"sim2real-check": CHECK},
    )["imageRecipeArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
