"""list-tags-resource-arn-missing-prefix-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-resource-arn-missing-prefix-rejected"
GROUP = "validation"
SERVICES = ["socialmessaging"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource rejects a resourceArn that does not start with "arn:" with ValidationException
    and its exact message, while a well-formed ARN of a resource that never existed returns an empty
    tag list rather than an error."""
    sm = ctx.client("socialmessaging")

    code, msg = _error(lambda: sm.list_tags_for_resource(resourceArn="not-an-arn"))
    assert code == "ValidationException", f"expected ValidationException, got {code}"
    expected_msg = "1 validation error detected: Value 'not-an-arn' at 'resourceArn' failed to satisfy constraint: Member must satisfy regular expression pattern: arn:.*"
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    account_id = ctx.client("sts").get_caller_identity()["Account"]
    nonexistent_arn = (
        f"arn:aws:social-messaging:{ctx.region}:{account_id}:"
        "phone-number-id/00000000-0000-0000-0000-000000000000"
    )
    response = sm.list_tags_for_resource(resourceArn=nonexistent_arn)
    assert response["tags"] == [], f"expected no tags for an unused resourceArn, got {response['tags']!r}"


def _error(fn):
    """Call fn(); return the (code, message) of its botocore error. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
