"""list-tags-for-resource-malformed-arn-validation."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tags-for-resource-malformed-arn-validation"
GROUP = "error-semantics"
SERVICES = ["controltower"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource rejects a non-ARN resourceArn with BadRequestException "Invalid input resource arn:
    bad syntax", and a well-formed unknown enabled-control ARN with NotFoundException "Resource was not
    found": both differ from the codes the model declares, and from each other."""
    ct = ctx.client("controltower")

    # Longer than the Arn shape's 20-character minimum, so botocore sends it to the service.
    malformed_arn = "totally-not-an-arn-but-long-enough"
    malformed_code, malformed_message = _error(
        lambda: ct.list_tags_for_resource(resourceArn=malformed_arn)
    )
    assert malformed_code == "BadRequestException", (
        f"expected BadRequestException for a malformed resourceArn, got {malformed_code}"
    )
    assert malformed_message == "Invalid input resource arn: bad syntax", (
        f"expected 'Invalid input resource arn: bad syntax' for a malformed resourceArn, "
        f"got {malformed_message!r}"
    )

    wellformed_missing_arn = (
        f"arn:aws:controltower:{ctx.region}:{_account_id(ctx)}:"
        "enabledcontrol/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    )
    wellformed_code, wellformed_message = _error(
        lambda: ct.list_tags_for_resource(resourceArn=wellformed_missing_arn)
    )
    assert wellformed_code == "NotFoundException", (
        f"expected NotFoundException for a well-formed but nonexistent resourceArn, "
        f"got {wellformed_code}"
    )
    assert wellformed_message == "Resource was not found", (
        f"expected 'Resource was not found' for a well-formed but nonexistent resourceArn, "
        f"got {wellformed_message!r}"
    )
    assert wellformed_code != malformed_code, (
        "malformed-input and not-found rejections must be distinguishable, got the "
        f"same code ({wellformed_code}) for both"
    )


def _error(fn):
    """``(code, message)`` of the rejection ``fn`` raises; an unexpected success raises."""
    # Deliberately does not catch botocore.exceptions.ParamValidationError.
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _account_id(ctx) -> str:
    return ctx.client("sts").get_caller_identity()["Account"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
