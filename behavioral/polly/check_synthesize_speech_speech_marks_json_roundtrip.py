"""synthesize-speech-speech-marks-json-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "synthesize-speech-speech-marks-json-roundtrip"
GROUP = "data-plane"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """OutputFormat=json with SpeechMarkTypes=[word] returns newline-delimited
    JSON documents describing each spoken word's offset and value -- real
    per-word timing/segmentation, not a stub echo of the input text."""
    polly = ctx.client("polly")
    text = "Hello wonderful world"

    resp = polly.synthesize_speech(
        Text=text,
        OutputFormat="json",
        VoiceId="Joanna",
        SpeechMarkTypes=["word"],
    )
    assert resp["ContentType"] == "application/x-json-stream"
    raw = resp["AudioStream"].read().decode("utf-8")
    lines = [line for line in raw.splitlines() if line.strip()]
    assert len(lines) == 3, f"expected exactly 3 word marks (one per word), got {len(lines)}: {raw!r}"

    marks = [json.loads(line) for line in lines]
    for mark in marks:
        assert mark["type"] == "word", f"expected type=word, got {mark['type']!r}: {mark!r}"
        assert isinstance(mark["time"], int) and mark["time"] >= 0, f"bad time in {mark!r}"
        assert isinstance(mark["start"], int) and isinstance(mark["end"], int), f"bad offsets in {mark!r}"
        assert mark["end"] > mark["start"], f"end must exceed start in {mark!r}"
        # start/end must be the word's real character offsets into the request text --
        # not merely present, so a stub that fabricates plausible-looking offsets is caught.
        assert text[mark["start"]:mark["end"]] == mark["value"], (
            f"start/end {mark['start']}:{mark['end']} slice text as "
            f"{text[mark['start']:mark['end']]!r}, expected {mark['value']!r}"
        )

    values = [m["value"] for m in marks]
    assert values == ["Hello", "wonderful", "world"], values
    # each word's audible synthesis takes real, non-zero time, so distinct words in one
    # sentence must be strictly increasing -- a stub faking ties would be caught here.
    times = [m["time"] for m in marks]
    assert times == sorted(set(times)) and len(set(times)) == len(times), times


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
