"""synthesize-speech-pcm-output-format."""
from __future__ import annotations

import struct

from behavioral_harness import tags

CHECK = "synthesize-speech-pcm-output-format"
GROUP = "data-plane"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SynthesizeSpeech with OutputFormat=pcm returns raw signed 16-bit mono little-endian
    samples (audio/pcm) that actually encode the input speech -- distinct from the
    compressed mp3 path, proportional to input length, and not a silent or fixed blob."""
    polly = ctx.client("polly")
    short_text = "Testing raw pcm output from Amazon Polly."
    long_text = short_text + " " + short_text

    def synth(text: str) -> bytes:
        resp = polly.synthesize_speech(
            Text=text,
            OutputFormat="pcm",
            SampleRate="16000",
            VoiceId="Joanna",
            Engine="standard",
        )
        assert resp["ContentType"] == "audio/pcm", resp["ContentType"]
        assert resp["RequestCharacters"] == len(text), (resp["RequestCharacters"], len(text))
        return resp["AudioStream"].read()

    audio = synth(short_text)
    long_audio = synth(long_text)

    assert len(audio) > 2000, f"unexpectedly small pcm payload: {len(audio)} bytes"
    # 16-bit samples: the byte stream must be an even length.
    assert len(audio) % 2 == 0, f"pcm stream must hold whole 16-bit samples, got {len(audio)} bytes"
    # PCM must not be MP3-framed audio mislabelled as pcm.
    assert not (audio[:3] == b"ID3" or audio[0] == 0xFF), (
        f"pcm payload looks mp3-framed, not raw pcm: leading bytes {audio[:4]!r}"
    )
    # Doubling the spoken text must roughly double the rendered pcm stream at a
    # fixed sample rate -- proof the payload tracks the actual input rather than
    # being a fixed-size or randomly-sized blob unrelated to what was synthesized.
    assert len(long_audio) > len(audio) * 1.5, (
        f"doubling the input text did not lengthen the pcm stream proportionally: "
        f"short={len(audio)} long={len(long_audio)}"
    )
    # A real rendering carries a nonzero signal, not silence.
    samples = struct.unpack(f"<{len(audio) // 2}h", audio[: len(audio) // 2 * 2])
    assert any(s != 0 for s in samples), "pcm payload is all-zero silence, not rendered speech"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
