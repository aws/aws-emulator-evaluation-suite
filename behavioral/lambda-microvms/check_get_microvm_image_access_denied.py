"""get-microvm-image-access-denied."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-microvm-image-access-denied"
GROUP = "overly-permissive"
SERVICES = ["lambda-microvms"]


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """GetMicrovmImage without the permission is AccessDeniedException with the exact message
    on an existing Lambda-managed image ARN and on a well-formed bogus ARN alike, so access
    is checked before existence."""
    client = ctx.client("lambda-microvms")
    items = client.list_managed_microvm_images().get("items", [])
    assert items, "expected at least one Lambda-managed base MicroVM image to probe against"
    # AWS names the calling principal's own ARN in the message.
    caller = ctx.client("sts").get_caller_identity()["Arn"]
    real_code, real_msg = _error(
        lambda: client.get_microvm_image(imageIdentifier=items[0]["imageArn"])
    )
    assert real_code == "AccessDeniedException", real_code
    assert real_msg == f"User: {caller} is not authorized to perform this operation", real_msg

    bogus_identifier = _bogus_image_arn(ctx)
    bogus_code, bogus_msg = _error(
        lambda: client.get_microvm_image(imageIdentifier=bogus_identifier)
    )
    assert bogus_code == "AccessDeniedException", bogus_code
    assert bogus_msg == (
        f"User: {caller} is not authorized to perform: lambda:GetMicrovmImage on resource: "
        f"{bogus_identifier}"
    ), bogus_msg


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
