"""tag-unicode-value-round-trip."""
from __future__ import annotations

from typing import Any, Callable

from behavioral_harness import tags

CHECK = "tag-unicode-value-round-trip"
GROUP = "server-side"
SERVICES = ["opensearchserverless"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Tags with CJK, accented and permitted punctuation characters round-trip through ListTagsForResource
    unchanged, while an emoji tag fails with ValidationException and its exact message and is not stored.
    """
    osc = ctx.client("opensearchserverless")
    name = ctx.unique_name("sim2real-tagunicode-")

    arn = None
    create_resp = osc.create_collection_group(name=name, standbyReplicas="DISABLED")[
        "createCollectionGroupDetail"
    ]
    arn = create_resp["arn"]
    group_id = create_resp["id"]
    ctx.on_cleanup(lambda: osc.delete_collection_group(id=group_id))

    tags = [
        {"key": "城市", "value": "东京-café"},
        {"key": "namé-clé", "value": "Ω-Δ-π-résumé"},
        {"key": "grüße", "value": "value_with.colons:and/slashes+plus=eq-dash"},
    ]
    osc.tag_resource(resourceArn=arn, tags=tags)

    stored = {t["key"]: t["value"] for t in osc.list_tags_for_resource(resourceArn=arn)["tags"]}
    for tag in tags:
        assert tag["key"] in stored, f"tag key {tag['key']!r} missing after round trip: {stored}"
        assert stored[tag["key"]] == tag["value"], (
            f"tag value for {tag['key']!r} mutated: expected {tag['value']!r}, got {stored[tag['key']]!r}"
        )

    # negative: a character outside AWS's allowed tag charset is rejected, not silently dropped
    emoji_tag = {"key": "launch🚀", "value": "🎉-party-2024"}
    code, message = _error(lambda: osc.tag_resource(resourceArn=arn, tags=[emoji_tag]))
    assert code == "ValidationException", f"expected ValidationException for emoji tag, got {code!r}"
    expected_message = (
        "Tags can only contain letters, numbers, spaces, and the following special characters: "
        "_ . : / = + - @"
    )
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: the rejected tag never appears on an independent read
    stored_after = {
        t["key"]: t["value"] for t in osc.list_tags_for_resource(resourceArn=arn)["tags"]
    }
    assert emoji_tag["key"] not in stored_after, (
        f"emoji tag key {emoji_tag['key']!r} present after a rejected TagResource: {stored_after}"
    )


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """Call fn(); return its error code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is None:
            raise
        error = response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
