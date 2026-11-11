"""retry-image-non-failed-state-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "retry-image-non-failed-state-rejected"
GROUP = "overly-permissive"
SERVICES = ["imagebuilder"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """RetryImage on a CANCELLED image fails with InvalidParameterValueException whose message has
    the fixed prefix and suffix around the build phase, the image stays CANCELLED, and tagging
    the same image still succeeds."""
    ib = ctx.client("imagebuilder")
    tag_key = ctx.unique_name("sim2real-ib-retry-")
    tag_map = {tag_key: "true"}

    profile_name = _create_instance_profile(ctx, tag_map)
    infra_arn = _create_infra_config_with_retry(ctx, ib, ctx.unique_name("sim2real-ib-infra-"), profile_name, tag_map)
    ctx.on_cleanup(lambda: ib.delete_infrastructure_configuration(infrastructureConfigurationArn=infra_arn))
    recipe_arn = _create_image_recipe(ctx, ib, tag_map)
    ctx.on_cleanup(lambda: ib.delete_image_recipe(imageRecipeArn=recipe_arn))

    image_arn = ib.create_image(
        infrastructureConfigurationArn=infra_arn,
        imageRecipeArn=recipe_arn,
        imageTestsConfiguration={"imageTestsEnabled": False},
        tags=tag_map,
        clientToken=str(uuid.uuid4()),
    )["imageBuildVersionArn"]
    ctx.on_cleanup(lambda: ib.delete_image(imageBuildVersionArn=image_arn))
    ctx.on_cleanup(lambda: _deregister_output_amis(ctx, ib, image_arn))

    ib.cancel_image_creation(imageBuildVersionArn=image_arn, clientToken=str(uuid.uuid4()))
    status = _poll_until_terminal(ib, image_arn)
    assert status == "CANCELLED", f"expected CANCELLED after cancel_image_creation, got {status!r}"

    code, message = _error(lambda: ib.retry_image(imageBuildVersionArn=image_arn, clientToken=str(uuid.uuid4())))
    assert code == "InvalidParameterValueException", f"expected InvalidParameterValueException, got {code!r}"
    # The message names the build phase the cancel landed in, which the check does not control, so
    # the text around that one phase name is pinned.
    head = (
        "The value supplied for parameter 'imageArn' is not valid. The provided image cannot be "
        "retried. Retry is not supported for images that failed during '"
    )
    tail = "' phase. Supported phases: TESTING, DISTRIBUTING"
    assert message.startswith(head) and message.endswith(tail), message

    # effect absent: the rejected retry did not move the build out of its cancelled terminal state
    status_after = ib.get_image(imageBuildVersionArn=image_arn)["image"]["state"]["status"]
    assert status_after == "CANCELLED", f"expected still CANCELLED after rejected retry, got {status_after!r}"

    # positive control: a state-appropriate mutation on the same cancelled image still succeeds and
    # is independently visible through a different read operation — proving RetryImage was rejected
    # for its state, not because the image is broadly unreachable
    control_tag_key = ctx.unique_name("sim2real-ib-retry-ctrl-")
    ib.tag_resource(resourceArn=image_arn, tags={control_tag_key: "true"})
    tags_after = ib.list_tags_for_resource(resourceArn=image_arn)["tags"]
    assert tags_after.get(control_tag_key) == "true", f"expected tag {control_tag_key!r} present, got {tags_after!r}"


def _error(fn):
    """``(code, message)`` of a refused call; an unexpected success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("expected a ClientError, call succeeded unexpectedly")


def _poll_until_terminal(ib, image_arn, timeout_s=240.0):
    deadline = time.monotonic() + timeout_s
    status = None
    while time.monotonic() < deadline:
        status = ib.get_image(imageBuildVersionArn=image_arn)["image"]["state"]["status"]
        if status in {"CANCELLED", "FAILED", "AVAILABLE", "DELETED"}:
            return status
        time.sleep(5)
    raise TimeoutError(f"image {image_arn} did not reach a terminal status within {timeout_s}s, last status {status!r}")


def _create_instance_profile(ctx, tag_map):
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-ib-profile-")
    trust = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
    )
    iam.create_role(RoleName=name, AssumeRolePolicyDocument=trust, Tags=_iam_tags(tag_map))
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=name))
    iam.create_instance_profile(InstanceProfileName=name, Tags=_iam_tags(tag_map))
    ctx.on_cleanup(lambda: iam.delete_instance_profile(InstanceProfileName=name))
    iam.add_role_to_instance_profile(InstanceProfileName=name, RoleName=name)
    ctx.on_cleanup(lambda: iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=name))
    return name


def _iam_tags(tag_map):
    return [{"Key": k, "Value": v} for k, v in tag_map.items()]


def _create_infra_config_with_retry(ctx, ib, name, profile_name, tag_map, timeout_s=90.0):
    deadline = time.monotonic() + timeout_s
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return ib.create_infrastructure_configuration(
                name=name, instanceProfileName=profile_name, tags=tag_map, clientToken=str(uuid.uuid4())
            )["infrastructureConfigurationArn"]
        except ClientError as exc:
            # IAM's instance-profile creation is eventually consistent; both codes surface the
            # same not-yet-visible-to-imagebuilder condition until it propagates.
            if exc.response["Error"]["Code"] not in ("InvalidRequestException", "InvalidParameterValueException"):
                raise
            last_exc = exc
            time.sleep(3)
    raise last_exc


def _create_image_recipe(ctx, ib, tag_map):
    parent_image = f"arn:aws:imagebuilder:{ctx.region}:aws:image/amazon-linux-2-x86/x.x.x"
    return ib.create_image_recipe(
        name=ctx.unique_name("sim2real-recipe-"),
        semanticVersion="1.0.0",
        parentImage=parent_image,
        tags=tag_map,
        clientToken=str(uuid.uuid4()),
    )["imageRecipeArn"]


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
