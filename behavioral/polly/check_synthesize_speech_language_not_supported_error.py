"""synthesize-speech-language-not-supported-error."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "synthesize-speech-language-not-supported-error"
GROUP = "error-semantics"
SERVICES = ["polly"]


@tags("axis:rejection", "cap:unclassified", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SynthesizeSpeech rejects a LanguageCode outside the enum with ValidationException, accepts a
    valid code that does not match the voice, and succeeds with the voice's own language code."""
    polly = ctx.client("polly")
    text = "Testing unsupported language code validation."

    bad_language = "xx-XX"
    code, message = _error(
        lambda: polly.synthesize_speech(
            Text=text,
            OutputFormat="mp3",
            VoiceId="Aditi",
            LanguageCode=bad_language,
        )
    )
    assert code == "ValidationException", code
    assert message == (
        f"1 validation error detected: Value '{bad_language}' at 'languageCode' failed to "
        "satisfy constraint: Member must satisfy enum value set: [en-IE, ar-AE, en-US, fr-BE, "
        "en-IN, es-MX, en-ZA, tr-TR, ru-RU, ro-RO, pt-PT, pl-PL, nl-NL, it-IT, is-IS, fr-FR, "
        "fi-FI, es-ES, de-DE, yue-CN, ko-KR, en-NZ, en-GB-WLS, hi-IN, de-CH, arb, nl-BE, cy-GB, "
        "cs-CZ, cmn-CN, da-DK, en-AU, pt-BR, nb-NO, sv-SE, ja-JP, es-US, ca-ES, fr-CA, en-GB, "
        "de-AT]"
    ), message

    # Documented permissiveness: a syntactically valid enum member that mismatches the voice's
    # own bilingual set (en-IN/hi-IN) is accepted, not rejected -- Polly falls back silently.
    mismatched = polly.synthesize_speech(
        Text=text, OutputFormat="mp3", VoiceId="Aditi", LanguageCode="fr-FR"
    )
    assert mismatched["ContentType"] == "audio/mpeg", mismatched["ContentType"]
    mismatched_audio = mismatched["AudioStream"].read()
    assert len(mismatched_audio) > 0, len(mismatched_audio)

    resp = polly.synthesize_speech(
        Text=text, OutputFormat="mp3", VoiceId="Aditi", LanguageCode="hi-IN"
    )
    assert resp["ContentType"] == "audio/mpeg", resp["ContentType"]
    resp_audio = resp["AudioStream"].read()
    assert len(resp_audio) > 0, len(resp_audio)


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, call succeeded instead: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
