"""tag-value-unicode-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "tag-value-unicode-round-trip"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A tag value with every non-alphanumeric separator Bedrock's Tag.value pattern allows is
    written via TagResource on a guardrail and returned byte-identical by ListTagsForResource."""
    bedrock = ctx.client("bedrock")
    name = ctx.unique_name("sim2real-behav-tagunicode-").replace("-", "_")
    created = bedrock.create_guardrail(
        name=name,
        blockedInputMessaging="blocked input",
        blockedOutputsMessaging="blocked output",
        wordPolicyConfig={"wordsConfig": [{"text": "sim2real-tagunicode-blockedword"}]},
    )
    guardrail_arn = created["guardrailArn"]
    guardrail_id = created["guardrailId"]
    ctx.on_cleanup(lambda: bedrock.delete_guardrail(guardrailIdentifier=guardrail_id))

    # Tag.value is constrained to `[a-zA-Z0-9\s._:/=+@-]*`, so multi-byte unicode is never
    # accepted; the allowed separators all appearing together are the case worth testing.
    special_value = "sim2real tag_value:with/separators=and+symbols@2024-01.01"
    tag_key = "sim2real-specialchars-tag"

    bedrock.tag_resource(resourceARN=guardrail_arn, tags=[{"key": tag_key, "value": special_value}])

    tags = bedrock.list_tags_for_resource(resourceARN=guardrail_arn)["tags"]
    matching = [t for t in tags if t["key"] == tag_key]
    assert len(matching) == 1, f"expected exactly one matching tag, got {matching}"
    assert matching[0]["value"] == special_value, (
        f"expected tag value {special_value!r}, got {matching[0]['value']!r}"
    )
    assert matching[0]["value"].encode("utf-8") == special_value.encode("utf-8"), (
        f"expected byte-identical utf-8 round trip for {special_value!r}, "
        f"got {matching[0]['value']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
