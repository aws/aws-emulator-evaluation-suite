"""concurrent-tag-resource-calls-merge-under-contention."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-tag-resource-calls-merge-under-contention"
GROUP = "concurrency"
SERVICES = ["bedrock-data-automation"]

_SCHEMA = (
    '{"class": "TagRace", "description": "concurrent tagging schema", '
    '"properties": {"x": {"type": "string", "inferenceType": "explicit", "instruction": "x"}}}'
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent TagResource calls, each adding a different key to one blueprint, all persist (tags
    merge, no lost update); after DeleteBlueprint, GetBlueprint and TagResource on its ARN return
    ResourceNotFoundException with their exact messages.
    """
    bda = ctx.client("bedrock-data-automation")
    name = ctx.unique_name("sim2real-bda-bp-tagrace")
    arn = bda.create_blueprint(blueprintName=name, type="DOCUMENT", schema=_SCHEMA)["blueprint"]["blueprintArn"]
    ctx.on_cleanup(lambda: _delete_ignore_missing(bda, arn))

    racers = 8
    expected = {f"key{i}": f"value{i}" for i in range(racers)}

    def _tag(i):
        bda.tag_resource(resourceARN=arn, tags=[{"key": f"key{i}", "value": f"value{i}"}])

    with ThreadPoolExecutor(max_workers=racers) as pool:
        list(pool.map(_tag, range(racers)))

    tags_after = {t["key"]: t["value"] for t in bda.list_tags_for_resource(resourceARN=arn)["tags"]}
    assert tags_after == expected, f"lost update under contention: {tags_after}"

    bda.delete_blueprint(blueprintArn=arn)

    get_code, get_message = _error_code(lambda: bda.get_blueprint(blueprintArn=arn))
    assert get_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from Get on a deleted blueprint, got {get_code!r}"
    )
    assert get_message == "Blueprint Arn not found.", f"unexpected Get message: {get_message!r}"

    tag_code, tag_message = _error_code(
        lambda: bda.tag_resource(resourceARN=arn, tags=[{"key": "post-delete", "value": "x"}])
    )
    assert tag_code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from TagResource on a deleted blueprint, got {tag_code!r}"
    )
    assert tag_message == f"Blueprint {arn} does not exist", f"unexpected TagResource message: {tag_message!r}"


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_ignore_missing(bda, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        bda.delete_blueprint(blueprintArn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
