"""detect-targeted-sentiment-mention-offsets-match-source."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-targeted-sentiment-mention-offsets-match-source"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectTargetedSentiment returns entity mentions whose offsets exactly bound the source substring."""
    comprehend = ctx.client("comprehend")
    text = "The battery life on this laptop is amazing, but the screen is disappointing."
    resp = comprehend.detect_targeted_sentiment(Text=text, LanguageCode="en")
    entities = resp["Entities"]
    assert entities, "expected at least one targeted-sentiment entity group"

    allowed_sentiments = {"POSITIVE", "NEGATIVE", "NEUTRAL", "MIXED"}
    for entity in entities:
        mentions = entity["Mentions"]
        assert mentions, f"entity group has no mentions: {entity!r}"
        descriptive_idx = entity["DescriptiveMentionIndex"]
        for idx in descriptive_idx:
            assert 0 <= idx < len(mentions), f"DescriptiveMentionIndex {idx} out of range for {mentions!r}"
        for mention in mentions:
            begin, end = mention["BeginOffset"], mention["EndOffset"]
            substring = text[begin:end]
            assert substring == mention["Text"], (
                f"mention offsets [{begin}:{end}] -> {substring!r} != reported Text {mention['Text']!r}"
            )
            assert mention["MentionSentiment"]["Sentiment"] in allowed_sentiments, mention
            score = mention["MentionSentiment"]["SentimentScore"]
            total = score["Positive"] + score["Negative"] + score["Neutral"] + score["Mixed"]
            assert abs(total - 1.0) < 0.02, f"mention sentiment scores do not sum to ~1.0: {score!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
