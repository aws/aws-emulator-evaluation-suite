"""list-tags-for-resource-nonexistent-not-found-exception."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-tags-for-resource-nonexistent-not-found-exception"
GROUP = "error-semantics"
SERVICES = ["synthetics"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListTagsForResource on a syntactically-valid but nonexistent ARN returns NotFoundException,
    not the ResourceNotFoundException used by the rest of the Synthetics API surface."""
    synth = ctx.client("synthetics")
    account = ctx.client("sts").get_caller_identity()["Account"]
    fake_group_arn = f"arn:aws:synthetics:{ctx.region}:{account}:group:sim2real-never-created"

    error = _client_error(lambda: synth.list_tags_for_resource(ResourceArn=fake_group_arn))
    assert error["Code"] == "NotFoundException", f"expected NotFoundException, got {error!r}"
    assert error["Message"] == "Resource was not found", (
        f"expected message 'Resource was not found', got {error['Message']!r}"
    )

    # Positive control: a real group's tags are listable without error (empty map when untagged).
    group_name = ctx.unique_name("sim2real-group-")
    group_arn = synth.create_group(Name=group_name, Tags={"env": "sim2real"})["Group"]["Arn"]
    ctx.on_cleanup(lambda: synth.delete_group(GroupIdentifier=group_name))

    tags = synth.list_tags_for_resource(ResourceArn=group_arn)["Tags"]
    assert tags == {"env": "sim2real"}


def _client_error(fn) -> dict:
    """Call fn() and return the botocore Error dict (Code, Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
