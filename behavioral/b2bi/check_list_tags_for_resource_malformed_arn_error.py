"""list-tags-for-resource-malformed-arn-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-tags-for-resource-malformed-arn-error"
GROUP = "overly-permissive"
SERVICES = ["b2bi"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource rejects a malformed ARN with ValidationException, while a real resource's
    ARN returns its tags."""
    b2bi = ctx.client("b2bi")

    resp = b2bi.create_profile(
        name=ctx.unique_name("sim2real-b2bi-profile-"),
        phone="+15555550100",
        businessName=ctx.unique_name("sim2real-b2bi-biz-"),
        logging="DISABLED",
        tags=[{"Key": "Environment", "Value": "sim2real-test"}],
    )
    profile_id = resp["profileId"]
    real_arn = resp["profileArn"]
    ctx.on_cleanup(lambda: b2bi.delete_profile(profileId=profile_id))

    malformed_arn = "this-is-not-an-arn-at-all"
    code, message = _error(lambda: b2bi.list_tags_for_resource(ResourceARN=malformed_arn))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected = f"Invalid ARN {malformed_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Positive control: the well-formed ARN of a real resource returns the tag this check attached.
    tags = b2bi.list_tags_for_resource(ResourceARN=real_arn)["Tags"]
    assert any(t["Key"] == "Environment" and t["Value"] == "sim2real-test" for t in tags), (
        f"expected the Environment=sim2real-test tag set at creation, got {tags!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(), which AWS refuses; return the ClientError's (code, message). An unexpected
    success raises, so accepting a request AWS refuses fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
