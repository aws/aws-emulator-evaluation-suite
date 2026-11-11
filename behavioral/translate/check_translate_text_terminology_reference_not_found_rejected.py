"""translate-text-terminology-reference-not-found-rejected."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "translate-text-terminology-reference-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["translate"]


def _client_error(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


@tags("axis:rejection", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """TranslateText rejects a TerminologyNames entry that doesn't exist, but a real terminology still works."""
    translate = ctx.client("translate")
    real_name = ctx.unique_name("sim2real-term-")
    translate.import_terminology(
        Name=real_name,
        MergeStrategy="OVERWRITE",
        TerminologyData={"File": b"en,es\nWidgetTerm,WidgetCustom\n", "Format": "CSV"},
        Tags=[{"Key": "sim2real", "Value": "true"}],
    )

    def _cleanup():
        try:
            translate.delete_terminology(Name=real_name)
        except ClientError as e:
            if e.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    missing_name = ctx.unique_name("sim2real-missing-term-")
    code, message = _client_error(
        lambda: translate.translate_text(
            Text="WidgetTerm",
            SourceLanguageCode="en",
            TargetLanguageCode="es",
            TerminologyNames=[missing_name],
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException for a never-created terminology name, got {code!r}"
    )
    expected = f"The Terminology for {ctx.account} {missing_name} was not found"
    assert message == expected, f"expected not-found message {expected!r}, got {message!r}"

    # positive control: referencing the real terminology succeeds and is applied. The input text
    # is exactly the source term, so the terminology is applied; a short bounded retry covers
    # propagation lag.
    deadline = time.time() + 30
    resp = None
    while time.time() < deadline:
        resp = translate.translate_text(
            Text="WidgetTerm",
            SourceLanguageCode="en",
            TargetLanguageCode="es",
            TerminologyNames=[real_name],
        )
        if resp.get("AppliedTerminologies") and "WidgetCustom" in resp["TranslatedText"]:
            break
        time.sleep(5)

    assert resp is not None, "translate_text with a real terminology never returned a response"
    assert "WidgetCustom" in resp["TranslatedText"], (
        f"expected the custom term to be applied, got translated text {resp['TranslatedText']!r} "
        f"applied={resp.get('AppliedTerminologies')!r}"
    )
    applied = resp["AppliedTerminologies"]
    assert len(applied) == 1, f"expected exactly one applied terminology, got {applied!r}"
    assert applied[0]["Name"] == real_name, (
        f"expected applied terminology name {real_name!r}, got {applied[0]['Name']!r}"
    )

    # the deleted terminology is gone (independent read) and unusable via the same operation
    # under test (TranslateText), not just absent from GetTerminology.
    translate.delete_terminology(Name=real_name)

    expected = f"The Terminology for {ctx.account} {real_name} was not found"
    code, message = _client_error(lambda: translate.get_terminology(Name=real_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetTerminology after delete, got {code!r}"
    )
    assert message == expected, f"expected not-found message {expected!r}, got {message!r}"

    code, message = _client_error(
        lambda: translate.translate_text(
            Text="WidgetTerm",
            SourceLanguageCode="en",
            TargetLanguageCode="es",
            TerminologyNames=[real_name],
        )
    )
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from TranslateText after delete, got {code!r}"
    )
    assert message == expected, f"expected not-found message {expected!r}, got {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
