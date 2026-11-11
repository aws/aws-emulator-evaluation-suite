"""list-image-pipelines-filters-by-name."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-image-pipelines-filters-by-name"
GROUP = "crud-roundtrip"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListImagePipelines with a name filter returns only the matching pipeline, not sibling pipelines."""
    ib = ctx.client("imagebuilder")
    component_arn = _create_component(ctx)
    recipe_arn = _create_image_recipe(ctx, component_arn)
    infra_arn = _create_infra_config(ctx)

    name_a = ctx.unique_name("sim2real-ib-pipe-a-")
    name_b = ctx.unique_name("sim2real-ib-pipe-b-")
    arn_a = ib.create_image_pipeline(
        name=name_a,
        imageRecipeArn=recipe_arn,
        infrastructureConfigurationArn=infra_arn,
        status="DISABLED",
        clientToken=str(uuid.uuid4()),
        tags={"sim2real-check": CHECK},
    )["imagePipelineArn"]
    ctx.on_cleanup(lambda: ib.delete_image_pipeline(imagePipelineArn=arn_a))
    arn_b = ib.create_image_pipeline(
        name=name_b,
        imageRecipeArn=recipe_arn,
        infrastructureConfigurationArn=infra_arn,
        status="DISABLED",
        clientToken=str(uuid.uuid4()),
        tags={"sim2real-check": CHECK},
    )["imagePipelineArn"]
    ctx.on_cleanup(lambda: ib.delete_image_pipeline(imagePipelineArn=arn_b))

    found = ib.list_image_pipelines(filters=[{"name": "name", "values": [name_a]}])["imagePipelineList"]
    found_arns = {p["arn"] for p in found}
    assert arn_a in found_arns, f"expected {arn_a} (name={name_a}) in name-filtered results, got {found_arns}"
    assert arn_b not in found_arns, (
        f"expected sibling pipeline {arn_b} (name={name_b}) excluded by the name_a filter, got {found_arns}"
    )


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
