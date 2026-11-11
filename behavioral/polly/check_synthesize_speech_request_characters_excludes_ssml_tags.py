"""synthesize-speech-request-characters-excludes-ssml-tags."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "synthesize-speech-request-characters-excludes-ssml-tags"
GROUP = "data-plane"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """RequestCharacters is a billing signal that counts only the spoken text,
    not SSML markup: wrapping the same words in <speak> tags must report the
    same billable character count as the identical plain text."""
    polly = ctx.client("polly")
    words = "Hello world this is a billing test"
    assert "<" not in words, f"test fixture must be markup-free, got {words!r}"

    plain = polly.synthesize_speech(Text=words, OutputFormat="mp3", VoiceId="Joanna")
    assert plain["RequestCharacters"] == len(words), (
        f"expected plain-text billing to equal input length: "
        f"got {plain['RequestCharacters']}, expected {len(words)}"
    )

    # Nested markup with an attribute, not just the outer <speak> wrapper, so a
    # stub that literal-strips "<speak>"/"</speak>" cannot pass by accident.
    ssml = f'<speak><prosody rate="slow">{words}</prosody></speak>'
    wrapped = polly.synthesize_speech(
        Text=ssml, OutputFormat="mp3", VoiceId="Joanna", TextType="ssml"
    )
    assert wrapped["RequestCharacters"] == len(words), (
        f"expected SSML tags excluded from billing count: "
        f"got {wrapped['RequestCharacters']}, expected {len(words)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
