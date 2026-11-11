"""list-tags-for-resource-malformed-arn-rejected."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-malformed-arn-rejected"
GROUP = "error-semantics"
SERVICES = ["acm"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource refuses a non-ARN identifier with ValidationException and a well-formed
    ARN of a missing acme-endpoint with ResourceNotFoundException, each with its exact message:
    syntax and existence are separate checks."""
    acm = ctx.client("acm")

    # The value is doubled to clear botocore's client-side minimum length, so the
    # service itself evaluates the malformed identifier.
    code, message = _error(
        lambda: acm.list_tags_for_resource(ResourceArn="not-an-arn-at-all" * 2)
    )
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected = (
        "1 validation error detected: Value of the input at 'resourceArn' failed to satisfy "
        "constraint: Member must satisfy regular expression pattern: "
        r"arn:[\w+=/,.@-]+:acm:[\w+=/,.@-]*:[0-9]+:[\w+=,.@-]+(/[\w+=,.@-]+)*"
    )
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # A well-formed acme-endpoint ARN that names nothing clears ARN validation and is
    # refused as not found, so the refusal above is about ARN syntax alone.
    account = ctx.client("sts").get_caller_identity()["Account"]
    fake_arn = f"arn:aws:acm:{ctx.region}:{account}:acme-endpoint/{uuid.uuid4()}"
    code2, message2 = _error(lambda: acm.list_tags_for_resource(ResourceArn=fake_arn))
    assert code2 == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a well-formed but unknown ARN, got {code2}"
    )
    expected2 = f"Could not find acme-endpoint {fake_arn}."
    assert message2 == expected2, f"expected message {expected2!r}, got {message2!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
