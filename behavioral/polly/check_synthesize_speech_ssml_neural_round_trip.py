"""synthesize-speech-ssml-neural-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "synthesize-speech-ssml-neural-round-trip"
GROUP = "data-plane"
SERVICES = ["polly"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """SynthesizeSpeech with TextType=ssml on the neural engine synthesizes audio and bills
    only the spoken text, not the SSML markup -- including a self-closing tag with an
    attribute (<break time="..."/>) that contributes no text of its own."""
    polly = ctx.client("polly")
    break_tag = '<break time="300ms"/>'
    sentence1 = "Hello there."
    sentence2 = "This is Polly speaking with SSML."
    ssml = f"<speak>{sentence1}{break_tag} {sentence2}</speak>"
    visible = f"{sentence1} {sentence2}"
    stripped = ssml.replace("<speak>", "").replace("</speak>", "").replace(break_tag, "")
    assert visible == stripped, (visible, stripped)

    plain = polly.synthesize_speech(
        Text=visible,
        TextType="text",
        OutputFormat="mp3",
        VoiceId="Joanna",
        Engine="neural",
    )
    assert plain["RequestCharacters"] == len(visible), (
        plain["RequestCharacters"],
        len(visible),
    )

    resp = polly.synthesize_speech(
        Text=ssml,
        TextType="ssml",
        OutputFormat="mp3",
        VoiceId="Joanna",
        Engine="neural",
    )
    assert resp["ContentType"] == "audio/mpeg", resp["ContentType"]
    audio = resp["AudioStream"].read()
    assert len(audio) > 1000, f"unexpectedly small mp3 payload: {len(audio)} bytes"
    assert audio[:3] == b"ID3" or audio[0] == 0xFF, audio[:4]
    # The break tag and its attribute contribute no billed characters: the SSML
    # call must report exactly the same RequestCharacters as the plain-text call
    # over the visible words alone, not merely "fewer than the raw markup".
    billed = resp["RequestCharacters"]
    assert billed == plain["RequestCharacters"], (
        f"expected SSML markup (including the self-closing <break/> tag) fully "
        f"excluded from billing: got {billed}, expected {plain['RequestCharacters']} "
        f"(the plain-text visible-words count)"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
