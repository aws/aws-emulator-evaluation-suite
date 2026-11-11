"""synthesize-speech-output-format-content-types."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "synthesize-speech-output-format-content-types"
GROUP = "data-plane"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """mp3, ogg_vorbis and pcm come back as audio/mpeg, audio/ogg and audio/pcm, each payload
    carries its codec's container signature, and the three encodings of one text differ
    byte-wise."""
    polly = ctx.client("polly")
    text = "Testing output format content types."

    expected = {
        "mp3": "audio/mpeg",
        "ogg_vorbis": "audio/ogg",
        "pcm": "audio/pcm",
    }
    payloads = {}
    for output_format, content_type in expected.items():
        resp = polly.synthesize_speech(
            Text=text, OutputFormat=output_format, VoiceId="Joanna"
        )
        assert resp["ContentType"] == content_type, (output_format, resp["ContentType"])
        assert resp["RequestCharacters"] == len(text), (
            output_format, resp["RequestCharacters"], len(text)
        )
        payload = resp["AudioStream"].read()
        assert len(payload) > 500, (output_format, len(payload))
        payloads[output_format] = payload

    mp3, ogg, pcm = payloads["mp3"], payloads["ogg_vorbis"], payloads["pcm"]

    # mp3: an 11-bit MPEG frame-sync, or an ID3 tag if one was prefixed.
    mp3_frame_sync = mp3[0] == 0xFF and (mp3[1] & 0xE0) == 0xE0
    assert mp3_frame_sync or mp3[:3] == b"ID3", f"mp3 payload has no MPEG/ID3 signature: {mp3[:8]!r}"

    # ogg_vorbis: every Ogg page starts with the "OggS" capture pattern.
    assert ogg[:4] == b"OggS", f"ogg_vorbis payload has no Ogg container signature: {ogg[:8]!r}"

    # pcm: raw 16-bit samples -- an even byte count, no compressed-format
    # framing, and a real (non-silent) signal.
    assert len(pcm) % 2 == 0, f"pcm stream must hold whole 16-bit samples, got {len(pcm)} bytes"
    assert not (pcm[:3] == b"ID3" or pcm[0] == 0xFF), f"pcm payload looks mp3-framed: {pcm[:4]!r}"
    assert any(b != 0 for b in pcm), "pcm payload is all-zero silence, not rendered speech"

    assert mp3 != ogg != pcm, (len(mp3), len(ogg), len(pcm))
    assert mp3 != pcm, (len(mp3), len(pcm))


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
