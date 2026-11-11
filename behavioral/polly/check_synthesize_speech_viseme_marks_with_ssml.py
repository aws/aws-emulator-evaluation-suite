"""synthesize-speech-viseme-marks-with-ssml."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "synthesize-speech-viseme-marks-with-ssml"
GROUP = "data-plane"
SERVICES = ["polly"]

# US English viseme codes Polly documents for SpeechMarkTypes=[viseme]
# (docs.aws.amazon.com/polly/latest/dg/viseme.html), plus the trailing
# end-of-speech silence mark -- a closed, voice-independent vocabulary.
KNOWN_VISEME_CODES = {
    "p", "t", "S", "T", "f", "k", "i", "r", "s", "u",
    "@", "a", "e", "E", "o", "O", "sil",
}


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SynthesizeSpeech with TextType=ssml and SpeechMarkTypes=[viseme] emits real viseme
    (mouth-shape) marks distinct from sentence/word marks, each carrying a viseme code."""
    polly = ctx.client("polly")
    text = "<speak>Hello world.</speak>"
    resp = polly.synthesize_speech(
        Text=text,
        TextType="ssml",
        OutputFormat="json",
        VoiceId="Joanna",
        SpeechMarkTypes=["viseme"],
    )
    assert resp["ContentType"] == "application/x-json-stream", resp["ContentType"]
    raw = resp["AudioStream"].read().decode("utf-8")
    lines = [line for line in raw.strip().split("\n") if line]
    marks = [json.loads(line) for line in lines]
    # two words decompose into several phonemes each; a stub that echoes one
    # mark per word (or a single placeholder mark) must not pass here.
    assert len(marks) > 2, f"expected multiple viseme marks for {text!r}, got {marks}"
    assert all(m["type"] == "viseme" for m in marks), marks
    for m in marks:
        assert m.get("value") in KNOWN_VISEME_CODES, (
            f"viseme value {m.get('value')!r} is not one of Polly's documented "
            f"viseme codes {sorted(KNOWN_VISEME_CODES)}"
        )
        assert isinstance(m.get("time"), int) and m["time"] >= 0, m
    # the mark stream ends with the mouth returning to its resting (silent) shape
    assert marks[-1]["value"] == "sil", f"expected trailing 'sil' mark, got {marks[-1]}"
    times = [m["time"] for m in marks]
    assert times == sorted(times), times


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
