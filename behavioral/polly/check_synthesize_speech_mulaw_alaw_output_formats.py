"""synthesize-speech-mulaw-alaw-output-formats."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "synthesize-speech-mulaw-alaw-output-formats"
GROUP = "data-plane"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """The lesser-used telephony encodings mu-law and a-law each render real, distinct audio
    with their own documented Content-Type at the required 8000 Hz sample rate."""
    polly = ctx.client("polly")
    text = "Testing telephony audio encodings."

    mulaw = polly.synthesize_speech(
        Text=text, OutputFormat="mulaw", SampleRate="8000", VoiceId="Joanna"
    )
    assert mulaw["ContentType"] == "audio/mulaw", mulaw["ContentType"]
    assert mulaw["RequestCharacters"] == len(text), mulaw["RequestCharacters"]
    mulaw_audio = mulaw["AudioStream"].read()
    assert len(mulaw_audio) > 500, len(mulaw_audio)
    # A fixed-fill stub would satisfy the length check alone; real 8-bit
    # companded speech is not a run of identical bytes.
    assert len(set(mulaw_audio)) > 10, sorted(set(mulaw_audio))

    alaw = polly.synthesize_speech(
        Text=text, OutputFormat="alaw", SampleRate="8000", VoiceId="Joanna"
    )
    assert alaw["ContentType"] == "audio/alaw", alaw["ContentType"]
    assert alaw["RequestCharacters"] == len(text), alaw["RequestCharacters"]
    alaw_audio = alaw["AudioStream"].read()
    assert len(alaw_audio) > 500, len(alaw_audio)
    assert len(set(alaw_audio)) > 10, sorted(set(alaw_audio))

    assert mulaw_audio != alaw_audio, "mulaw and alaw companding must render distinct bytes"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
