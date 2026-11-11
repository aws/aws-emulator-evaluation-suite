"""get-microvm-image-build-access-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-microvm-image-build-access-denied"
GROUP = "overly-permissive"
SERVICES = ["lambda-microvms"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """List/GetMicrovmImageBuild on a real managed image version and Get on a bogus image all answer
    AccessDeniedException: authorization is checked before resource existence.
    """
    client = ctx.client("lambda-microvms")

    images = client.list_managed_microvm_images().get("items", [])
    assert images, "expected at least one Lambda-managed base MicroVM image to probe against"
    image_arn = images[0]["imageArn"]

    versions = client.list_managed_microvm_image_versions(imageIdentifier=image_arn).get("items", [])
    assert versions, f"expected at least one version for managed image {image_arn}"
    image_version = versions[0]["imageVersion"]

    # AWS names the calling principal's own ARN in the message.
    caller = ctx.client("sts").get_caller_identity()["Arn"]
    denied = f"User: {caller} is not authorized to perform this operation"
    real_list_code, real_list_msg = _error(
        lambda: client.list_microvm_image_builds(imageIdentifier=image_arn, imageVersion=image_version)
    )
    assert real_list_code == "AccessDeniedException", real_list_code
    assert real_list_msg == denied, real_list_msg

    real_get_code, real_get_msg = _error(
        lambda: client.get_microvm_image_build(
            imageIdentifier=image_arn,
            imageVersion=image_version,
            buildId=ctx.unique_name("probe-build-"),
        )
    )
    assert real_get_code == "AccessDeniedException", real_get_code
    assert real_get_msg == denied, real_get_msg

    bogus_image = _bogus_image_arn(ctx)
    code, message = _error(
        lambda: client.get_microvm_image_build(
            imageIdentifier=bogus_image, imageVersion="1.0", buildId="build-does-not-exist"
        )
    )
    assert code == "AccessDeniedException", code
    assert message == (
        f"User: {caller} is not authorized to perform: lambda:GetMicrovmImageBuild on resource: "
        f"{bogus_image}"
    ), message


def _bogus_image_arn(ctx) -> str:
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    region = ctx.region or "us-east-1"
    tail = ctx.unique_name("missing-image-").replace("_", "-")
    return f"arn:aws:lambda:{region}:{account_id}:microvm-image/{tail}"


def _error(fn) -> tuple[str, str]:
    """(code, message) of the ClientError fn() raises; a success raises."""
    try:
        fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError("the call unexpectedly SUCCEEDED where real AWS rejects it")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
