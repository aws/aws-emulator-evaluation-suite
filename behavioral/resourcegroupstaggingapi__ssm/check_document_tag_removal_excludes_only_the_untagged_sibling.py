"""document-tag-removal-excludes-only-the-untagged-sibling."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "document-tag-removal-excludes-only-the-untagged-sibling"
GROUP = "tagging-discovery"
SERVICES = ["resourcegroupstaggingapi", "ssm"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


_CONTENT = (
    '{"schemaVersion": "2.2", "description": "sim2real", "mainSteps": '
    '[{"action": "aws:runShellScript", "name": "noop", "inputs": {"runCommand": ["true"]}}]}'
)


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Removing one SSM document's tag drops only that document from the tagging API's
    GetResources index; a sibling document carrying the same tag key stays discoverable."""
    ssm = ctx.client("ssm")
    rgt = ctx.client("resourcegroupstaggingapi")

    key = ctx.unique_name("sim2real-behav-k-")
    name_a = ctx.unique_name("sim2real-behav-doc-a-")
    name_b = ctx.unique_name("sim2real-behav-doc-b-")
    value_a = ctx.unique_name("sim2real-behav-va-")
    value_b = ctx.unique_name("sim2real-behav-vb-")
    arn_a = f"arn:aws:ssm:{ctx.region}:{ctx.account}:document/{name_a}"
    arn_b = f"arn:aws:ssm:{ctx.region}:{ctx.account}:document/{name_b}"

    ssm.create_document(Name=name_a, Content=_CONTENT, DocumentType="Command",
                         Tags=[{"Key": key, "Value": value_a}])
    ctx.on_cleanup(_teardown(lambda: ssm.delete_document(Name=name_a), "InvalidDocument"))

    ssm.create_document(Name=name_b, Content=_CONTENT, DocumentType="Command",
                         Tags=[{"Key": key, "Value": value_b}])
    ctx.on_cleanup(_teardown(lambda: ssm.delete_document(Name=name_b), "InvalidDocument"))

    # Positive control for the whole query: both documents are in the index under this key
    # before either tag is touched, so the later absence is the removal excluding, not a lagging
    # index that never picked either one up.
    both = _poll_until(
        lambda: {
            m["ResourceARN"]
            for m in rgt.get_resources(
                ResourceTypeFilters=["ssm:document"],
                TagFilters=[{"Key": key}],
            )["ResourceTagMappingList"]
        },
        lambda arns: arns == {arn_a, arn_b},
        timeout_s=120.0,
    )
    assert both == {arn_a, arn_b}, (
        f"tag query for {key!r} returned {sorted(both)!r} before any removal, expected both documents"
    )

    ssm.remove_tags_from_resource(ResourceType="Document", ResourceId=name_a, TagKeys=[key])

    after = _poll_until(
        lambda: {
            m["ResourceARN"]
            for m in rgt.get_resources(
                ResourceTypeFilters=["ssm:document"],
                TagFilters=[{"Key": key}],
            )["ResourceTagMappingList"]
        },
        lambda arns: arns == {arn_b},
        timeout_s=120.0,
    )
    assert after == {arn_b}, (
        f"after RemoveTagsFromResource on {name_a!r}, the tag query returned {sorted(after)!r}; "
        f"expected only the untouched sibling {arn_b!r}"
    )

    native_a = ssm.list_tags_for_resource(ResourceType="Document", ResourceId=name_a)["TagList"]
    pairs_a = {t["Key"]: t["Value"] for t in native_a}
    assert key not in pairs_a, f"ListTagsForResource still reports {key!r} on {name_a!r}: {pairs_a!r}"

    native_b = ssm.list_tags_for_resource(ResourceType="Document", ResourceId=name_b)["TagList"]
    pairs_b = {t["Key"]: t["Value"] for t in native_b}
    assert pairs_b.get(key) == value_b, (
        f"the untouched sibling {name_b!r} lost its own tag: {pairs_b!r}"
    )


def _poll_until(probe, predicate, timeout_s=120.0, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    last = probe()
    while time.monotonic() < deadline:
        if predicate(last):
            return last
        time.sleep(interval_s)
        last = probe()
    return last


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
