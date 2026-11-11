"""model-card-unicode-content-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "model-card-unicode-content-roundtrip"
GROUP = "representation"
SERVICES = ["sagemaker"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ModelCard Content field containing unicode text and deeply nested JSON is
    persisted and returned unchanged (same parsed structure and same literal strings,
    including emoji and non-Latin scripts) by DescribeModelCard."""
    sm = ctx.client("sagemaker")

    content = {
        "model_overview": {
            "model_description": "Ünïcödé regression model — 日本語 説明 🎉",
            "model_creator": "sim2real-tëam",
            "problem_type": "Regression",
        },
        "intended_uses": {
            "purpose_of_model": "Validate unicode round-trip: café, résumé, 北京, naïve",
            "risk_rating": "Low",
        },
        "additional_information": {
            "custom_details": {
                "nested_note": "deep nested ünïcödé value 🚀🔥",
                "another_note": "emoji stress test: 😀😃😄😁 中文 العربية",
            }
        },
    }
    content_str = json.dumps(content, ensure_ascii=False)

    card_name = ctx.unique_name("sim2real-mc-")
    sm.create_model_card(
        ModelCardName=card_name, Content=content_str, ModelCardStatus="Draft"
    )
    ctx.on_cleanup(lambda: sm.delete_model_card(ModelCardName=card_name))

    desc = sm.describe_model_card(ModelCardName=card_name)
    assert desc["ModelCardName"] == card_name, (
        f"expected ModelCardName {card_name!r}, got {desc['ModelCardName']!r}"
    )
    assert desc["ModelCardStatus"] == "Draft", (
        f"expected ModelCardStatus 'Draft', got {desc['ModelCardStatus']!r}"
    )

    # Byte-identical: no re-encoding, whitespace normalization or key reordering.
    assert desc["Content"] == content_str, (
        f"Content was not returned byte-identical: sent {content_str!r}, got {desc['Content']!r}"
    )

    round_tripped = json.loads(desc["Content"])
    assert round_tripped == content, (
        f"parsed content diverged from what was sent: expected {content!r}, got {round_tripped!r}"
    )
    # Spot-check the literal unicode bytes survived, not just structural equality.
    assert "🎉" in desc["Content"], f"emoji '🎉' missing from returned Content: {desc['Content']!r}"
    assert "日本語" in desc["Content"], f"'日本語' missing from returned Content: {desc['Content']!r}"
    assert "😀😃😄😁" in desc["Content"], (
        f"emoji sequence '😀😃😄😁' missing from returned Content: {desc['Content']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
