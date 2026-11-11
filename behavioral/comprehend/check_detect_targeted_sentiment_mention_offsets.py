"""detect-targeted-sentiment-mention-offsets."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-targeted-sentiment-mention-offsets"
GROUP = "inference"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectTargetedSentiment returns per-entity mentions whose text and offsets
    are self-consistent with the source document, and whose sentiment fields are
    drawn from the documented enumeration."""
    comprehend = ctx.client("comprehend")
    text = "The food was delicious but the service was terrible."
    resp = comprehend.detect_targeted_sentiment(Text=text, LanguageCode="en")
    entities = resp["Entities"]
    assert entities, "expected at least one targeted-sentiment entity"

    valid_sentiments = {"POSITIVE", "NEGATIVE", "NEUTRAL", "MIXED"}
    mention_count = 0
    for entity in entities:
        mentions = entity["Mentions"]
        assert mentions, "each entity must have at least one mention"
        for mention in mentions:
            mention_count += 1
            begin, end = mention["BeginOffset"], mention["EndOffset"]
            substring = text[begin:end]
            assert substring == mention["Text"], (
                f"mention offsets [{begin}:{end}] -> {substring!r} != reported Text {mention['Text']!r}"
            )
            assert mention["MentionSentiment"]["Sentiment"] in valid_sentiments, (
                f"unexpected sentiment {mention['MentionSentiment']['Sentiment']!r}, "
                f"expected one of {sorted(valid_sentiments)}"
            )
    assert mention_count >= 2, "expected mentions for both 'food' and 'service'"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
