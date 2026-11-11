"""create-image-pipeline-duplicate-name-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-image-pipeline-duplicate-name-rejected"
GROUP = "error-semantics"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateImagePipeline with a name already in use in the account/region is rejected."""
    ib = ctx.client("imagebuilder")
    component_arn = _create_component(ctx)
    recipe_arn = _create_image_recipe(ctx, component_arn)
    infra_arn = _create_infra_config(ctx)

    name = ctx.unique_name("sim2real-ib-pipe-")
    created = ib.create_image_pipeline(
        name=name,
        imageRecipeArn=recipe_arn,
        infrastructureConfigurationArn=infra_arn,
        status="DISABLED",
        clientToken=str(uuid.uuid4()),
    )
    pipeline_arn = created["imagePipelineArn"]
    ctx.on_cleanup(lambda: ib.delete_image_pipeline(imagePipelineArn=pipeline_arn))

    code, msg = _error(
        lambda: ib.create_image_pipeline(
            name=name,
            imageRecipeArn=recipe_arn,
            infrastructureConfigurationArn=infra_arn,
            status="DISABLED",
            clientToken=str(uuid.uuid4()),
        )
    )
    assert code == "ResourceAlreadyExistsException", f"expected ResourceAlreadyExistsException, got {code!r}"
    expected = f"The following resource 'Pipeline' already exists: '{pipeline_arn}'."
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # effect absent: the rejected duplicate did not register a second pipeline
    # under this name — an independent read at the destination, not the mutating
    # call's own response.
    found = ib.list_image_pipelines(filters=[{"name": "name", "values": [name]}])["imagePipelineList"]
    assert len(found) == 1, f"expected exactly one pipeline named {name!r}, found {len(found)}"
    assert found[0]["arn"] == pipeline_arn, f"expected {pipeline_arn}, found {found[0]['arn']}"

    # positive control: a distinct name succeeds
    other_name = ctx.unique_name("sim2real-ib-pipe-")
    other = ib.create_image_pipeline(
        name=other_name,
        imageRecipeArn=recipe_arn,
        infrastructureConfigurationArn=infra_arn,
        status="DISABLED",
        clientToken=str(uuid.uuid4()),
    )
    other_arn = other["imagePipelineArn"]
    ctx.on_cleanup(lambda: ib.delete_image_pipeline(imagePipelineArn=other_arn))

    # independent read confirming the positive control actually registered,
    # rather than trusting create_image_pipeline's own response.
    got_other = ib.get_image_pipeline(imagePipelineArn=other_arn)["imagePipeline"]
    assert got_other["name"] == other_name, f"expected {other_name!r}, got {got_other['name']!r}"


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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
