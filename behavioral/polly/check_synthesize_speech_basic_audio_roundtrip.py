"""synthesize-speech-basic-audio-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "synthesize-speech-basic-audio-roundtrip"
GROUP = "data-plane"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SynthesizeSpeech actually renders audio: the response carries a
    non-trivial MP3 byte stream, the declared ContentType, and a
    RequestCharacters count that matches the input text length."""
    polly = ctx.client("polly")
    text = "The quick brown fox jumps over the lazy dog."

    resp = polly.synthesize_speech(Text=text, OutputFormat="mp3", VoiceId="Joanna")
    assert resp["ContentType"] == "audio/mpeg", (
        f"expected audio/mpeg, got {resp['ContentType']}"
    )
    assert resp["RequestCharacters"] == len(text), (
        f"expected RequestCharacters={len(text)}, got {resp['RequestCharacters']}"
    )

    audio = resp["AudioStream"].read()
    assert len(audio) > 1000, f"suspiciously small audio payload: {len(audio)} bytes"
    # MP3 frames start with an 11-bit frame-sync (0xFF, top 3 bits of next byte
    # set) or, if a tag is present, an ID3 header.
    is_frame_sync = audio[0] == 0xFF and (audio[1] & 0xE0) == 0xE0
    assert is_frame_sync or audio[:3] == b"ID3", audio[:8]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
