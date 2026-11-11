"""list-image-packages-nonexistent-image-returns-empty."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-image-packages-nonexistent-image-returns-empty"
GROUP = "error-semantics"
SERVICES = ["imagebuilder"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListImagePackages on a well-formed image ARN that was never built returns an empty
    imagePackageList, while a malformed ARN fails with InvalidParameterValueException and its
    exact message."""
    ib = ctx.client("imagebuilder")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    bogus_name = ctx.unique_name("sim2real-ib-nonexistent-image-")
    bogus_arn = f"arn:aws:imagebuilder:{ctx.region}:{account_id}:image/{bogus_name}/1.0.0/1"

    resp = ib.list_image_packages(imageBuildVersionArn=bogus_arn)
    assert resp.get("imagePackageList", []) == [], f"expected an empty package list, got {resp!r}"

    # positive control: a *malformed* ARN (missing the build-version node) is rejected outright,
    # proving ListImagePackages does perform shape validation and is not simply swallowing every
    # input into an empty answer.
    malformed_arn = f"arn:aws:imagebuilder:{ctx.region}:{account_id}:image/{bogus_name}/1.0.0"
    try:
        ib.list_image_packages(imageBuildVersionArn=malformed_arn)
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        assert code == "InvalidParameterValueException", (
            f"expected InvalidParameterValueException for a malformed ARN, got {code!r}"
        )
        message = exc.response["Error"].get("Message")
        expected = (
            "The value supplied for parameter 'imageBuildVersionArn' is not valid. imageBuildVersionArn must match "
            "pattern ^arn:aws(?:-[a-z]+)*:imagebuilder:[a-z]{2,}(?:-[a-z]+)+-[0-9]+:(?:[0-9]{12}|aws(?:-[a-z-]+)?):"
            "image/[a-z0-9-_]+/[0-9]+\\.[0-9]+\\.[0-9]+/[0-9]+$"
        )
        assert message == expected, f"expected message {expected!r}, got {message!r}"
    else:
        raise AssertionError("expected a malformed imageBuildVersionArn to be rejected, but it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
