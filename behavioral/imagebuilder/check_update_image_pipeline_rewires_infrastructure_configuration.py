"""update-image-pipeline-rewires-infrastructure-configuration."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-image-pipeline-rewires-infrastructure-configuration"
GROUP = "state-machine"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateImagePipeline can rewire a pipeline onto a different infrastructureConfigurationArn."""
    ib = ctx.client("imagebuilder")
    component_arn = _create_component(ctx)
    recipe_arn = _create_image_recipe(ctx, component_arn)
    infra_arn_a = _create_infra_config(ctx)
    infra_arn_b = _create_infra_config(ctx)

    name = ctx.unique_name("sim2real-ib-pipe-")
    created = ib.create_image_pipeline(
        name=name,
        imageRecipeArn=recipe_arn,
        infrastructureConfigurationArn=infra_arn_a,
        status="DISABLED",
        clientToken=str(uuid.uuid4()),
    )
    pipeline_arn = created["imagePipelineArn"]
    def _delete_pipeline_if_present() -> None:
        try:
            ib.delete_image_pipeline(imagePipelineArn=pipeline_arn)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_delete_pipeline_if_present)

    got = ib.get_image_pipeline(imagePipelineArn=pipeline_arn)["imagePipeline"]
    assert got["infrastructureConfigurationArn"] == infra_arn_a, (
        f"expected freshly-created pipeline to report infra config {infra_arn_a!r}, "
        f"got {got['infrastructureConfigurationArn']!r}"
    )

    ib.update_image_pipeline(
        imagePipelineArn=pipeline_arn,
        imageRecipeArn=recipe_arn,
        infrastructureConfigurationArn=infra_arn_b,
        status="DISABLED",
        clientToken=str(uuid.uuid4()),
    )

    got_after = ib.get_image_pipeline(imagePipelineArn=pipeline_arn)["imagePipeline"]
    assert got_after["infrastructureConfigurationArn"] == infra_arn_b, (
        f"expected UpdateImagePipeline to rewire the pipeline onto {infra_arn_b!r}, "
        f"got {got_after['infrastructureConfigurationArn']!r}"
    )
    assert got_after["infrastructureConfigurationArn"] != infra_arn_a, (
        f"pipeline still reports the old infra config {infra_arn_a!r} after rewiring to {infra_arn_b!r}"
    )

    ib.delete_image_pipeline(imagePipelineArn=pipeline_arn)
    try:
        ib.get_image_pipeline(imagePipelineArn=pipeline_arn)
    except ClientError as e:
        assert e.response["Error"]["Code"] == "ResourceNotFoundException", (
            f"expected ResourceNotFoundException reading a deleted pipeline, got {e.response['Error']['Code']!r}"
        )
        message = e.response["Error"].get("Message")
        expected = f"The following required resource 'ImagePipeline' cannot be found: '{pipeline_arn}'."
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError("expected GetImagePipeline to fail after DeleteImagePipeline, but it returned a result")


def _create_instance_profile(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ib-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
    }
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.create_instance_profile(InstanceProfileName=role_name)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=role_name, RoleName=role_name))
    return role_name


def _create_infra_config(ctx, **extra) -> str:
    ib = ctx.client("imagebuilder")
    profile = _create_instance_profile(ctx)
    name = ctx.unique_name("sim2real-ib-infra-")
    deadline = time.monotonic() + 90.0
    last_exc = None
    while time.monotonic() < deadline:
        try:
            resp = ib.create_infrastructure_configuration(
                name=name, instanceProfileName=profile, clientToken=str(uuid.uuid4()), **extra
            )
            break
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("InvalidParameterValueException", "InvalidRequestException"):
                last_exc = e
                time.sleep(5)
                continue
            raise
    else:
        raise last_exc
    arn = resp["infrastructureConfigurationArn"]
    ctx.on_cleanup(lambda: ib.delete_infrastructure_configuration(infrastructureConfigurationArn=arn))
    return arn


def _create_component(ctx, version: str = "1.0.0", platform: str = "Linux") -> str:
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-comp-")
    doc = (
        f"name: {name}\n"
        "description: test component\n"
        "schemaVersion: 1.0\n"
        "phases:\n"
        "  - name: build\n"
        "    steps:\n"
        "      - name: UpdateOS\n"
        "        action: UpdateOS\n"
    )
    resp = ib.create_component(
        name=name, semanticVersion=version, platform=platform, data=doc, clientToken=str(uuid.uuid4())
    )
    arn = resp["componentBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_component(componentBuildVersionArn=arn))
    return arn


def _latest_al2_ami(ctx) -> str:
    ssm = ctx.client("ssm")
    return ssm.get_parameter(Name="/aws/service/ami-amazon-linux-latest/amzn2-ami-hvm-x86_64-gp2")["Parameter"][
        "Value"
    ]


def _create_image_recipe(ctx, component_arn: str, version: str = "1.0.0") -> str:
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-recipe-")
    parent = _latest_al2_ami(ctx)
    resp = ib.create_image_recipe(
        name=name,
        semanticVersion=version,
        parentImage=parent,
        components=[{"componentArn": component_arn}],
        clientToken=str(uuid.uuid4()),
    )
    arn = resp["imageRecipeArn"]
    ctx.on_cleanup(lambda: ib.delete_image_recipe(imageRecipeArn=arn))
    return arn


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
