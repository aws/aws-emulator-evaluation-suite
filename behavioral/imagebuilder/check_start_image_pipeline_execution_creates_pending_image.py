"""start-image-pipeline-execution-creates-pending-image."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "start-image-pipeline-execution-creates-pending-image"
GROUP = "state-machine"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control")
def run(ctx) -> None:
    """StartImagePipelineExecution on an ENABLED pipeline drives a real image into PENDING/BUILDING."""
    ib = ctx.client("imagebuilder")
    component_arn = _create_component(ctx)
    recipe_arn = _create_image_recipe(ctx, component_arn)
    infra_arn = _create_infra_config(ctx)

    name = ctx.unique_name("sim2real-ib-pipe-")
    created = ib.create_image_pipeline(
        name=name,
        imageRecipeArn=recipe_arn,
        infrastructureConfigurationArn=infra_arn,
        imageTestsConfiguration={"imageTestsEnabled": False},
        status="ENABLED",
        clientToken=str(uuid.uuid4()),
    )
    pipeline_arn = created["imagePipelineArn"]
    ctx.on_cleanup(lambda: ib.delete_image_pipeline(imagePipelineArn=pipeline_arn))

    started = ib.start_image_pipeline_execution(imagePipelineArn=pipeline_arn, clientToken=str(uuid.uuid4()))
    image_arn = started["imageBuildVersionArn"]
    ctx.on_cleanup(lambda: _try_cancel(ib, image_arn))
    ctx.on_cleanup(lambda: ib.delete_image(imageBuildVersionArn=image_arn))

    forward_states = ("PENDING", "CREATING", "BUILDING", "TESTING", "DISTRIBUTING", "AVAILABLE")
    got = _poll_until(
        lambda: ib.get_image(imageBuildVersionArn=image_arn)["image"]["state"]["status"],
        lambda status: status in forward_states,
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert got in forward_states, f"expected forward progress, got {got!r}"

    # independent read at the pipeline's own image list, not just the image's own get:
    # a target that fabricates an image ARN without wiring it to the pipeline fails here.
    pipeline_images = ib.list_image_pipeline_images(imagePipelineArn=pipeline_arn)["imageSummaryList"]
    assert any(img["arn"] == image_arn for img in pipeline_images), (
        f"{image_arn} not present in list_image_pipeline_images for {pipeline_arn}: {pipeline_images}"
    )


# ===== helpers =====
def _try_cancel(ib, image_arn: str) -> None:
    """Cancel the build; only a gone or already-terminal build is tolerated."""
    try:
        ib.cancel_image_creation(imageBuildVersionArn=image_arn, clientToken=str(uuid.uuid4()))
    except ClientError as exc:
        if exc.response["Error"]["Code"] not in ("ResourceNotFoundException", "InvalidParameterValueException"):
            raise


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


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
