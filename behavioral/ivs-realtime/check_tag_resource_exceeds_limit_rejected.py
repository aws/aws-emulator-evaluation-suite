"""tag-resource-exceeds-limit-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-resource-exceeds-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs-realtime"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource rejects a request that would push a resource over the documented
    50-tag limit with ValidationException, none of the offending batch is applied
    (all-or-nothing), and tagging within the limit succeeds (positive control)."""
    client = ctx.client("ivs-realtime")
    stage_arn = client.create_stage(name=ctx.unique_name("sim2real-stage"))["stage"]["arn"]
    ctx.on_cleanup(lambda: client.delete_stage(arn=stage_arn))

    too_many_tags = {f"k{i}": f"v{i}" for i in range(51)}
    code, message = _error(lambda: client.tag_resource(resourceArn=stage_arn, tags=too_many_tags))
    assert code == "BadRequestException", (
        f"TagResource with 51 tags returned {code!r}, not BadRequestException"
    )
    expected_message = "The resultant tag set must not have more than 50 user tags."
    assert message == expected_message, f"expected {expected_message!r}, got {message!r}"

    # Effect absent: none of the offending batch got applied.
    tags_after = client.list_tags_for_resource(resourceArn=stage_arn)["tags"]
    assert tags_after == {}, (
        f"the rejected 51-tag batch was applied anyway: {tags_after!r}"
    )

    # Positive control: a within-limit batch is accepted and persists.
    ok_tags = {f"k{i}": f"v{i}" for i in range(10)}
    client.tag_resource(resourceArn=stage_arn, tags=ok_tags)
    tags_after_ok = client.list_tags_for_resource(resourceArn=stage_arn)["tags"]
    assert tags_after_ok == ok_tags, (
        f"a within-limit 10-tag batch did not persist: expected {ok_tags!r}, got {tags_after_ok!r}"
    )


def _error(fn):
    """The AWS error (code, message) for a call that MUST fail.

    An unexpected SUCCESS raises rather than returning a falsy sentinel: an emulator accepting input
    real AWS refuses is the strongest signal available.
    """
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected TagResource to be rejected, but it SUCCEEDED: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
