"""create-image-pipeline-missing-recipe-arn-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-image-pipeline-missing-recipe-arn-rejected"
GROUP = "overly-permissive"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateImagePipeline requires exactly one of imageRecipeArn/containerRecipeArn; omitting both is rejected with MissingParametersException and no pipeline is created."""
    ib = ctx.client("imagebuilder")
    profile_name = _create_instance_profile(ctx)
    infra_arn = _create_infra_config_with_retry(ctx, ib, ctx.unique_name("sim2real-ib-infra-"), profile_name)
    ctx.on_cleanup(lambda: ib.delete_infrastructure_configuration(infrastructureConfigurationArn=infra_arn))

    pipeline_name = ctx.unique_name("sim2real-pipeline-")
    code, msg = _error(
        lambda: ib.create_image_pipeline(
            name=pipeline_name,
            infrastructureConfigurationArn=infra_arn,
            clientToken=str(uuid.uuid4()),
        )
    )
    assert code == "MissingParametersException", f"expected MissingParametersException, got {code!r}"
    expected = (
        "Required parameters are missing from the request: 'imageRecipeArn' or 'containerRecipeArn'. "
        "Verify that you have entered all of the required parameters in your request and try again."
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # effect absent: no pipeline was registered under this name
    found = ib.list_image_pipelines(filters=[{"name": "name", "values": [pipeline_name]}])["imagePipelineList"]
    assert found == [], f"expected no pipeline registered under {pipeline_name!r}, found {found!r}"

    # positive control: supplying exactly one recipe arn succeeds
    recipe_arn = _create_image_recipe(ctx, ib)
    control_arn = ib.create_image_pipeline(
        name=pipeline_name,
        infrastructureConfigurationArn=infra_arn,
        imageRecipeArn=recipe_arn,
        status="DISABLED",
        clientToken=str(uuid.uuid4()),
    )["imagePipelineArn"]
    ctx.on_cleanup(lambda: ib.delete_image_pipeline(imagePipelineArn=control_arn))


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


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
    arn = ib.create_image_recipe(
        name=ctx.unique_name("sim2real-recipe-"),
        semanticVersion="1.0.0",
        parentImage=parent_image,
        clientToken=str(uuid.uuid4()),
    )["imageRecipeArn"]
    ctx.on_cleanup(lambda: ib.delete_image_recipe(imageRecipeArn=arn))
    return arn



if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
