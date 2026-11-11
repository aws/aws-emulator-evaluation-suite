"""list-tags-for-resource-not-found."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-not-found"
GROUP = "errors"
SERVICES = ["elementalinference"]


def _error(fn):
    """The AWS error code and message `fn` raises; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a well-formed but nonexistent dictionary ARN returns NotFoundException (the
    tagging control plane's generic not-found shape, distinct from the service's own ResourceNotFoundException
    used by the resource-specific Get*/Delete* operations)."""
    ei = ctx.client("elementalinference")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    # Positive control: ListTagsForResource must actually work on a real, existing resource --
    # otherwise the rejection below is indistinguishable from "rejects every call".
    name = ctx.unique_name("sim2real-ei-dict-")
    resp = ei.create_dictionary(
        name=name, language="eng",
        entries='[{"content": "ace"}]',
        tags={"Environment": "sim2real-behav"},
    )
    dict_id = resp["id"]
    ctx.on_cleanup(lambda: ei.delete_dictionary(id=dict_id))
    real_tags = ei.list_tags_for_resource(resourceArn=resp["arn"])["tags"]
    assert real_tags == {"Environment": "sim2real-behav"}, real_tags

    arn = f"arn:aws:elemental-inference:{ctx.region}:{account_id}:dictionary/nonexistent00001"
    code, message = _error(lambda: ei.list_tags_for_resource(resourceArn=arn))
    assert code == "NotFoundException", code
    expected_message = "Resource was not found"
    assert message == expected_message, (
        f"NotFoundException carried the message {message!r}, expected {expected_message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
