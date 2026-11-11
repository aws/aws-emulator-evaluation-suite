"""synthesize-speech-ssml-prosody-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "synthesize-speech-ssml-prosody-roundtrip"
GROUP = "data-plane"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:c3", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SSML <prosody rate="x-slow"> renders a longer audio stream than the same sentence as plain
    text, so the SSML is parsed and applied."""
    polly = ctx.client("polly")
    sentence = "This sentence is spoken at a different rate."
    plain = polly.synthesize_speech(
        Text=sentence, OutputFormat="pcm", VoiceId="Joanna", TextType="text"
    )["AudioStream"].read()

    ssml = f'<speak><prosody rate="x-slow">{sentence}</prosody></speak>'
    slow = polly.synthesize_speech(
        Text=ssml, OutputFormat="pcm", VoiceId="Joanna", TextType="ssml"
    )["AudioStream"].read()

    assert len(plain) > 0 and len(slow) > 0, f"plain={len(plain)} slow={len(slow)}"
    # x-slow roughly halves the speaking rate, so the slowed PCM stream (fixed
    # sample rate/bit depth) must be substantially longer than the plain one.
    assert len(slow) > len(plain) * 1.3, f"plain={len(plain)} slow={len(slow)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
