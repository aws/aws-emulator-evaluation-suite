"""detect-targeted-sentiment-returns-consistent-mention-offsets."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-targeted-sentiment-returns-consistent-mention-offsets"
GROUP = "data-plane"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectTargetedSentiment groups per-entity mentions with valid sentiment labels, and every
    mention's offsets slice back to exactly its own reported mention text."""
    comprehend = ctx.client("comprehend")
    text = "The pizza was delicious but the service was awful."

    resp = comprehend.detect_targeted_sentiment(Text=text, LanguageCode="en")
    entities = resp["Entities"]
    assert len(entities) > 0, "expected at least one targeted-sentiment entity"

    valid_sentiments = {"POSITIVE", "NEGATIVE", "NEUTRAL", "MIXED"}
    sentiment_by_mention_text: dict[str, str] = {}
    for entity in entities:
        mentions = entity["Mentions"]
        assert len(mentions) > 0, entity
        descriptive_idx = entity["DescriptiveMentionIndex"]
        for idx in descriptive_idx:
            assert 0 <= idx < len(mentions), (
                f"DescriptiveMentionIndex {idx} out of range for {mentions!r}"
            )
        for mention in mentions:
            begin, end = mention["BeginOffset"], mention["EndOffset"]
            assert text[begin:end] == mention["Text"], (
                f"offset [{begin}:{end}] does not slice back to {mention['Text']!r}"
            )
            sentiment = mention["MentionSentiment"]["Sentiment"]
            assert sentiment in valid_sentiments, mention
            score = mention["MentionSentiment"]["SentimentScore"]
            total = score["Positive"] + score["Negative"] + score["Neutral"] + score["Mixed"]
            assert abs(total - 1.0) < 0.02, f"mention sentiment scores do not sum to ~1.0: {score!r}"
            sentiment_by_mention_text[mention["Text"].lower()] = sentiment

    # Comprehend's targeted-sentiment model ties "pizza" to the "delicious" clause and
    # "service" to the "awful" clause.
    assert sentiment_by_mention_text.get("pizza") == "POSITIVE", (
        f"expected 'pizza' mention sentiment POSITIVE, mentions were {sentiment_by_mention_text!r}"
    )
    assert sentiment_by_mention_text.get("service") == "NEGATIVE", (
        f"expected 'service' mention sentiment NEGATIVE, mentions were {sentiment_by_mention_text!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
