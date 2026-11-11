"""delete-infrastructure-configuration-in-use-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-infrastructure-configuration-in-use-rejected"
GROUP = "overly-permissive"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Deleting an infrastructure configuration still referenced by an image pipeline is rejected until the pipeline is removed."""
    ib = ctx.client("imagebuilder")
    profile_name = _create_instance_profile(ctx)
    infra_arn = _create_infra_config_with_retry(ctx, ib, ctx.unique_name("sim2real-ib-infra-"), profile_name)
    ctx.on_cleanup(lambda: _safe(lambda: ib.delete_infrastructure_configuration(infrastructureConfigurationArn=infra_arn)))

    recipe_arn = _create_image_recipe(ctx, ib)
    ctx.on_cleanup(lambda: _safe(lambda: ib.delete_image_recipe(imageRecipeArn=recipe_arn)))

    pipeline_arn = ib.create_image_pipeline(
        name=ctx.unique_name("sim2real-pipeline-"),
        infrastructureConfigurationArn=infra_arn,
        imageRecipeArn=recipe_arn,
        status="DISABLED",
        clientToken=str(uuid.uuid4()),
    )["imagePipelineArn"]
    ctx.on_cleanup(lambda: _safe(lambda: ib.delete_image_pipeline(imagePipelineArn=pipeline_arn)))

    code, message = _error(lambda: ib.delete_infrastructure_configuration(infrastructureConfigurationArn=infra_arn))
    assert code == "ResourceDependencyException", f"expected ResourceDependencyException, got {code!r}"
    expected = f"The resource ARN '{infra_arn}' has dependent resources"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the infrastructure configuration still exists
    got = ib.get_infrastructure_configuration(infrastructureConfigurationArn=infra_arn)["infrastructureConfiguration"]
    assert got["arn"] == infra_arn, f"infrastructure configuration disappeared after a rejected delete: {got!r}"

    # positive control: after removing the dependent pipeline, deletion succeeds
    ib.delete_image_pipeline(imagePipelineArn=pipeline_arn)
    ib.delete_image_recipe(imageRecipeArn=recipe_arn)
    ib.delete_infrastructure_configuration(infrastructureConfigurationArn=infra_arn)

    # independent read at the destination: the infrastructure configuration is actually gone
    not_found = f"The resource ARN '{infra_arn}' was not found."
    code_after, message_after = _error(lambda: ib.get_infrastructure_configuration(infrastructureConfigurationArn=infra_arn))
    assert code_after == "ResourceNotFoundException", f"expected ResourceNotFoundException after delete, got {code_after!r}"
    assert message_after == not_found, f"expected message {not_found!r}, got {message_after!r}"

    # a second delete on the now-dead id fails with the same not-found code, not a silent success
    code_double, message_double = _error(lambda: ib.delete_infrastructure_configuration(infrastructureConfigurationArn=infra_arn))
    assert code_double == "ResourceNotFoundException", f"expected ResourceNotFoundException on double delete, got {code_double!r}"
    assert message_double == not_found, f"expected message {not_found!r}, got {message_double!r}"


# ===== helpers =====
def _safe(fn):
    """Run a teardown delete; only an already-deleted resource is tolerated."""
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
