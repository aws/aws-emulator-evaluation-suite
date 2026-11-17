"""create-image-recipe-version-and-image-pipeline-arn-roundtrip."""

from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-image-recipe-version-and-image-pipeline-arn-roundtrip"
GROUP = "control-plane"
SERVICES = ["iam", "imagebuilder", "logs"]

# The fresh-profile visibility transient, the only error the infrastructure create retries.
_PROFILE_NOT_VISIBLE = (
    "InvalidParameterValueException",
    "The value supplied for parameter 'instanceProfileName' is not valid. The provided instance "
    "profile does not exist. Please specify a different instance profile and try again.",
)


def _budget_s(ctx, cap_s):
    """A poll's timeout: cap_s, bounded by the runner's remaining time less 5 s so the poll fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


_COMPONENT_DATA = """
name: sim2real-test-component
description: minimal test component for an image recipe and pipeline
schemaVersion: 1.0

phases:
  - name: build
    steps:
      - name: HelloWorldStep
        action: ExecuteBash
        inputs:
          commands:
            - echo "hello world"
""".strip()

_COMPONENT_VERSION = "2.1.4"
_RECIPE_VERSION = "3.2.1"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetComponent and GetImageRecipe echo each submitted semanticVersion, which is the ARN's
    version segment; the pipeline ARN names the account, region and pipeline name, and a deleted
    pipeline reads back as ResourceNotFoundException."""
    ib = ctx.client("imagebuilder")

    component_name = ctx.unique_name("sim2real-component-")
    component_arn = ib.create_component(
        name=component_name,
        semanticVersion=_COMPONENT_VERSION,
        platform="Linux",
        data=_COMPONENT_DATA,
        clientToken=str(uuid.uuid4()),
        tags={"sim2real": CHECK},
    )["componentBuildVersionArn"]
    ctx.on_cleanup(
        _ignore_not_found(lambda: ib.delete_component(componentBuildVersionArn=component_arn))
    )
    partition = component_arn.split(":")[1]
    expected_component_arn = (
        f"arn:{partition}:imagebuilder:{ctx.region}:{ctx.account}:component/"
        f"{component_name}/{_COMPONENT_VERSION}/1"
    )
    assert component_arn == expected_component_arn, (
        f"expected componentBuildVersionArn {expected_component_arn!r}, got {component_arn!r}"
    )
    got_component = ib.get_component(componentBuildVersionArn=component_arn)["component"]
    assert (got_component["arn"], got_component["version"]) == (
        component_arn,
        _COMPONENT_VERSION,
    ), (
        f"expected arn/version {(component_arn, _COMPONENT_VERSION)!r}, got "
        f"{(got_component['arn'], got_component['version'])!r}"
    )

    recipe_name = ctx.unique_name("sim2real-recipe-")
    parent_image = f"arn:{partition}:imagebuilder:{ctx.region}:aws:image/amazon-linux-2-x86/x.x.x"
    recipe_arn = ib.create_image_recipe(
        name=recipe_name,
        semanticVersion=_RECIPE_VERSION,
        parentImage=parent_image,
        components=[{"componentArn": component_arn}],
        clientToken=str(uuid.uuid4()),
        tags={"sim2real": CHECK},
    )["imageRecipeArn"]
    ctx.on_cleanup(_ignore_not_found(lambda: ib.delete_image_recipe(imageRecipeArn=recipe_arn)))
    expected_recipe_arn = f"arn:{partition}:imagebuilder:{ctx.region}:{ctx.account}:image-recipe/{recipe_name}/{_RECIPE_VERSION}"
    assert recipe_arn == expected_recipe_arn, (
        f"expected imageRecipeArn {expected_recipe_arn!r}, got {recipe_arn!r}"
    )
    got_recipe = ib.get_image_recipe(imageRecipeArn=recipe_arn)["imageRecipe"]
    assert (got_recipe["arn"], got_recipe["version"]) == (recipe_arn, _RECIPE_VERSION), (
        f"expected arn/version {(recipe_arn, _RECIPE_VERSION)!r}, got "
        f"{(got_recipe['arn'], got_recipe['version'])!r}"
    )

    profile_name = _create_instance_profile(ctx)
    infra_arn = _create_infra_config_with_retry(ctx, profile_name)
    ctx.on_cleanup(
        lambda: ib.delete_infrastructure_configuration(infrastructureConfigurationArn=infra_arn)
    )

    pipeline_name = ctx.unique_name("sim2real-pipeline-")
    # Registered before the create, so LIFO reaps the pipeline's log group after its own delete.
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/imagebuilder/pipeline/{pipeline_name}"))
    pipeline_arn = ib.create_image_pipeline(
        name=pipeline_name,
        imageRecipeArn=recipe_arn,
        infrastructureConfigurationArn=infra_arn,
        status="DISABLED",
        clientToken=str(uuid.uuid4()),
        tags={"sim2real": CHECK},
    )["imagePipelineArn"]
    ctx.on_cleanup(
        _ignore_not_found(lambda: ib.delete_image_pipeline(imagePipelineArn=pipeline_arn))
    )
    expected_pipeline_arn = (
        f"arn:{partition}:imagebuilder:{ctx.region}:{ctx.account}:image-pipeline/{pipeline_name}"
    )
    assert pipeline_arn == expected_pipeline_arn, (
        f"expected imagePipelineArn {expected_pipeline_arn!r}, got {pipeline_arn!r}"
    )
    got_pipeline = ib.get_image_pipeline(imagePipelineArn=pipeline_arn)["imagePipeline"]
    assert (got_pipeline["arn"], got_pipeline["imageRecipeArn"]) == (pipeline_arn, recipe_arn), (
        f"expected arn/imageRecipeArn {(pipeline_arn, recipe_arn)!r}, got "
        f"{(got_pipeline['arn'], got_pipeline['imageRecipeArn'])!r}"
    )

    ib.delete_image_pipeline(imagePipelineArn=pipeline_arn)
    got_error = _error(lambda: ib.get_image_pipeline(imagePipelineArn=pipeline_arn))
    pipeline_gone = (
        "ResourceNotFoundException",
        f"The following required resource 'ImagePipeline' cannot be found: '{pipeline_arn}'.",
    )
    assert got_error == pipeline_gone, f"expected {pipeline_gone!r}, got {got_error!r}"


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


def _ignore_not_found(fn):
    """Teardown wrapper: a resource the check already deleted reads as not-found; anything else raises."""

    def go():
        try:
            fn()
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    return go


def _reap_log_group(logs, name, *, reads=3, interval_s=5.0, budget_s=180.0):
    """Delete log group ``name`` until ``reads`` consecutive reads find it absent.

    An image pipeline's log group can materialise after the pipeline that owns it is gone.
    """
    deadline = time.monotonic() + budget_s
    absent = 0
    while absent < reads:
        groups = logs.describe_log_groups(logGroupNamePrefix=name)["logGroups"]
        if any(g["logGroupName"] == name for g in groups):
            absent = 0
            try:
                logs.delete_log_group(logGroupName=name)
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                    raise
        else:
            absent += 1
        if absent < reads:
            if time.monotonic() > deadline:
                raise AssertionError(
                    f"log group {name} still present after {budget_s}s of deletes; {absent} clean reads"
                )
            time.sleep(interval_s)


def _create_instance_profile(ctx) -> str:
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-ib-role-")
    trust = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"Service": "ec2.amazonaws.com"},
                "Action": "sts:AssumeRole",
            }
        ],
    }
    iam_tags = [{"Key": "sim2real", "Value": CHECK}]
    iam.create_role(RoleName=role_name, AssumeRolePolicyDocument=json.dumps(trust), Tags=iam_tags)
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.create_instance_profile(InstanceProfileName=role_name, Tags=iam_tags)
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=role_name))
    iam.add_role_to_instance_profile(InstanceProfileName=role_name, RoleName=role_name)
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(
            InstanceProfileName=role_name, RoleName=role_name
        )
    )
    return role_name


def _create_infra_config_with_retry(ctx, profile_name: str, timeout_s: float = 90.0) -> str:
    """create_infrastructure_configuration, retrying only the fresh-profile visibility transient."""
    ib = ctx.client("imagebuilder")
    name = ctx.unique_name("sim2real-ib-infra-")
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ib.create_infrastructure_configuration(
                name=name,
                instanceProfileName=profile_name,
                clientToken=str(uuid.uuid4()),
                tags={"sim2real": CHECK},
            )["infrastructureConfigurationArn"]
        except ClientError as exc:
            err = exc.response["Error"]
            if (err.get("Code"), err.get("Message")) != _PROFILE_NOT_VISIBLE:
                raise
            if time.monotonic() >= deadline:
                if _budget_spent(ctx):
                    raise TimeoutError(
                        "instance profile visibility: the run budget ended first; not graded"
                    ) from exc
                raise
        time.sleep(3)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
