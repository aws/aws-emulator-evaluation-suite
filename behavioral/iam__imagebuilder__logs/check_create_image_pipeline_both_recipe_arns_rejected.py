"""create-image-pipeline-both-recipe-arns-rejected."""

from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-image-pipeline-both-recipe-arns-rejected"
GROUP = "overly-permissive"
SERVICES = ["iam", "imagebuilder", "logs"]

_BOTH_RECIPES = (
    "InvalidParameterCombinationException",
    "The value supplied for parameter 'imageRecipeArn' and 'containerRecipeArn' is not valid. "
    "You must specify either imageRecipeArn or containerRecipeArn.",
)
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


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateImagePipeline naming both an image recipe and a container recipe is refused with
    InvalidParameterCombinationException and no pipeline is listed; naming only the image recipe
    creates a pipeline that reports that recipe and no container recipe."""
    ib = ctx.client("imagebuilder")
    profile_name = _create_instance_profile(ctx)
    infra_arn = _create_infra_config_with_retry(
        ctx, ib, ctx.unique_name("sim2real-ib-infra-"), profile_name
    )
    ctx.on_cleanup(
        lambda: ib.delete_infrastructure_configuration(infrastructureConfigurationArn=infra_arn)
    )
    partition = infra_arn.split(":")[1]
    recipe_arn = _create_image_recipe(ctx, ib, partition)

    # A syntactically valid but never-created container recipe ARN: the rejection fires on the
    # parameter combination itself, before either ARN is resolved against an existing resource.
    bogus_container_arn = (
        f"arn:{partition}:imagebuilder:{ctx.region}:{ctx.account}:container-recipe/"
        f"{ctx.unique_name('sim2real-ib-unused-')}/1.0.0"
    )
    pipeline_name = ctx.unique_name("sim2real-pipeline-")
    # An unexpected success still creates a pipeline: its delete is registered before the call.
    accepted = {}
    ctx.on_cleanup(
        lambda: (
            ib.delete_image_pipeline(imagePipelineArn=accepted["arn"])
            if accepted.get("arn")
            else None
        )
    )

    def create_with_both_recipes():
        accepted["arn"] = ib.create_image_pipeline(
            name=pipeline_name,
            infrastructureConfigurationArn=infra_arn,
            imageRecipeArn=recipe_arn,
            containerRecipeArn=bogus_container_arn,
            clientToken=str(uuid.uuid4()),
        )["imagePipelineArn"]
        return accepted["arn"]

    got_error = _error(create_with_both_recipes)
    assert got_error == _BOTH_RECIPES, f"expected {_BOTH_RECIPES!r}, got {got_error!r}"

    # effect absent: no pipeline was registered under this name
    found = ib.list_image_pipelines(filters=[{"name": "name", "values": [pipeline_name]}])[
        "imagePipelineList"
    ]
    assert found == [], f"expected no pipeline registered under {pipeline_name!r}, found {found!r}"

    # positive control: supplying exactly one recipe arn succeeds
    # Registered before the create, so LIFO reaps the pipeline's log group after its own delete.
    logs = ctx.client("logs")
    ctx.on_cleanup(lambda: _reap_log_group(logs, f"/aws/imagebuilder/pipeline/{pipeline_name}"))
    control_arn = ib.create_image_pipeline(
        name=pipeline_name,
        infrastructureConfigurationArn=infra_arn,
        imageRecipeArn=recipe_arn,
        status="DISABLED",
        clientToken=str(uuid.uuid4()),
    )["imagePipelineArn"]
    ctx.on_cleanup(lambda: ib.delete_image_pipeline(imagePipelineArn=control_arn))
    got = ib.get_image_pipeline(imagePipelineArn=control_arn)["imagePipeline"]
    have = (got.get("imageRecipeArn"), "containerRecipeArn" in got)
    assert have == (recipe_arn, False), f"control pipeline {got!r}"


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


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(
        f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}"
    )


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
    ctx.on_cleanup(
        lambda: iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=name)
    )
    return name


def _create_infra_config_with_retry(ctx, ib, name, profile_name, timeout_s=90.0):
    """create_infrastructure_configuration, retrying only the fresh-profile visibility transient."""
    timeout_s = _budget_s(ctx, timeout_s)
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            return ib.create_infrastructure_configuration(
                name=name, instanceProfileName=profile_name, clientToken=str(uuid.uuid4())
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


def _create_image_recipe(ctx, ib, partition):
    parent_image = f"arn:{partition}:imagebuilder:{ctx.region}:aws:image/amazon-linux-2-x86/x.x.x"
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
