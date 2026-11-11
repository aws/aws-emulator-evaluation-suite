"""describe-voices-language-filter."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-voices-language-filter"
GROUP = "state"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeVoices filtered by LanguageCode returns only voices for that language, and
    includes at least one well-known French voice."""
    polly = ctx.client("polly")
    resp = polly.describe_voices(LanguageCode="fr-FR")
    voices = resp["Voices"]
    assert len(voices) > 0, "expected at least one fr-FR voice"
    assert all(v["LanguageCode"] == "fr-FR" for v in voices), voices

    ids = {v["Id"] for v in voices}
    known_fr_voices = {"Lea", "Mathieu", "Celine", "Remi"}
    assert ids & known_fr_voices, f"no known fr-FR voice in {ids}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
