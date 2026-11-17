"""list-tags-for-resource-malformed-arn-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-malformed-arn-rejected"
GROUP = "activities"
SERVICES = ["stepfunctions"]

_MALFORMED_ARN = "sim2real-not-an-arn"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. An unexpected
    SUCCESS raises, naming what came back."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected ListTagsForResource to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource given a string that is not an ARN fails with InvalidArn and the
    exact message, while the real ARN of a tagged resource returns the tags it was created
    with."""
    sfn = ctx.client("stepfunctions")
    name = ctx.unique_name("sim2real-behav-act-")
    arn = sfn.create_activity(
        name=name, tags=[{"key": "sim2real", "value": "1"}, {"key": "owner", "value": "fidelity"}],
    )["activityArn"]
    ctx.on_cleanup(lambda: sfn.delete_activity(activityArn=arn))

    tags_resp = sfn.list_tags_for_resource(resourceArn=arn)["tags"]
    assert {(t["key"], t["value"]) for t in tags_resp} == {("sim2real", "1"), ("owner", "fidelity")}, (
        f"ListTagsForResource returned {tags_resp!r} for the resource created with those two tags"
    )

    code, message = _error(lambda: sfn.list_tags_for_resource(resourceArn=_MALFORMED_ARN))
    assert code == "InvalidArn", f"expected InvalidArn, got {code!r}: {message!r}"
    expected = f"Invalid Arn: 'Invalid ARN prefix: {_MALFORMED_ARN}'"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
