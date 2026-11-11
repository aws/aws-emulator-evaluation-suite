"""tag-resource-round-trip."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tag-resource-round-trip"
GROUP = "state"
SERVICES = ["mgn"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource, ListTagsForResource and UntagResource on a well-formed but nonexistent application
    ARN each fail with NotFoundException, not UninitializedAccountException and not a success.
    """
    mgn = ctx.client("mgn")
    account = ctx.client("sts").get_caller_identity()["Account"]
    fake_arn = f"arn:aws:mgn:{ctx.region}:{account}:application/app-00000000000000000"

    code, message = _expect_rejected(
        lambda: mgn.tag_resource(resourceArn=fake_arn, tags={"sim2real-key": "sim2real-value"}),
        "TagResource",
    )
    assert code == "NotFoundException", f"TagResource on a nonexistent ARN got {code!r}"
    assert message == "Resource was not found", f"TagResource on a nonexistent ARN answered {message!r}"

    code, message = _expect_rejected(
        lambda: mgn.list_tags_for_resource(resourceArn=fake_arn),
        "ListTagsForResource",
    )
    assert code == "NotFoundException", f"ListTagsForResource on a nonexistent ARN got {code!r}"
    assert message == "Resource was not found", f"ListTagsForResource on a nonexistent ARN answered {message!r}"

    code, message = _expect_rejected(
        lambda: mgn.untag_resource(resourceArn=fake_arn, tagKeys=["sim2real-key"]),
        "UntagResource",
    )
    assert code == "NotFoundException", f"UntagResource on a nonexistent ARN got {code!r}"
    assert message == "Resource was not found", f"UntagResource on a nonexistent ARN answered {message!r}"


def _expect_rejected(fn, label):
    try:
        result = fn()
        raise AssertionError(f"{label} against a nonexistent application ARN unexpectedly succeeded: {result!r}")
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
