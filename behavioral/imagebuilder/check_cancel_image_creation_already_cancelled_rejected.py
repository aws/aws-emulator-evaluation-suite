"""cancel-image-creation-already-cancelled-rejected."""
from __future__ import annotations

import json
import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cancel-image-creation-already-cancelled-rejected"
GROUP = "overly-permissive"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "cap:c4", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Cancelling an image build already in a terminal CANCELLED state is rejected."""
    ib = ctx.client("imagebuilder")
    component_arn = _create_component(ctx)
    recipe_arn = _create_image_recipe(ctx, component_arn)
    infra_arn = _create_infra_config(ctx)

    created = ib.create_image(
        infrastructureConfigurationArn=infra_arn,
        imageRecipeArn=recipe_arn,
        imageTestsConfiguration={"imageTestsEnabled": False},
        clientToken=str(uuid.uuid4()),
        tags={"sim2real": CHECK},
    )
    image_arn = created["imageBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_image(imageBuildVersionArn=image_arn))
    ctx.on_cleanup(lambda: _deregister_output_amis(ctx, ib, image_arn))

    # positive control: the first cancel succeeds and reaches CANCELLED
    ib.cancel_image_creation(imageBuildVersionArn=image_arn, clientToken=str(uuid.uuid4()))
    status = _poll_until(
        lambda: ib.get_image(imageBuildVersionArn=image_arn)["image"]["state"]["status"],
        lambda s: s in ("CANCELLED", "FAILED", "AVAILABLE"),
        timeout_s=180.0,
        interval_s=5.0,
    )
    assert status == "CANCELLED", f"expected the first cancel to reach CANCELLED, got {status!r}"

    # negative: cancelling again is rejected because the build is already terminal
    code, msg = _error(
        lambda: ib.cancel_image_creation(imageBuildVersionArn=image_arn, clientToken=str(uuid.uuid4()))
    )
    assert code == "InvalidParameterValueException", (
        f"expected a second cancel on an already-CANCELLED build to be rejected with "
        f"InvalidParameterValueException, got {code!r}"
    )
    expected = (
        "The value supplied for parameter 'imageArn' is not valid. "
        "The provided image is in a terminal state and cannot be cancelled."
    )
    assert msg == expected, f"expected message {expected!r}, got {msg!r}"

    # effect absent: status is still CANCELLED, unaffected by the rejected second cancel
    status_after = ib.get_image(imageBuildVersionArn=image_arn)["image"]["state"]["status"]
    assert status_after == "CANCELLED", (
        f"the rejected second cancel must not have moved the build off CANCELLED, got {status_after!r}"
    )


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last}")


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
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(trust),
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))
    iam.create_instance_profile(InstanceProfileName=role_name, Tags=[{"Key": "sim2real", "Value": CHECK}])
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
                name=name,
                instanceProfileName=profile,
                clientToken=str(uuid.uuid4()),
                tags={"sim2real": CHECK},
                **extra,
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
        name=name,
        semanticVersion=version,
        platform=platform,
        data=doc,
        clientToken=str(uuid.uuid4()),
        tags={"sim2real": CHECK},
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
        tags={"sim2real": CHECK},
    )
    arn = resp["imageRecipeArn"]
    ctx.on_cleanup(lambda: ib.delete_image_recipe(imageRecipeArn=arn))
    return arn


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
