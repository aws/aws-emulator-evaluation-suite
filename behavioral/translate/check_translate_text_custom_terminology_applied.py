"""translate-text-custom-terminology-applied."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "translate-text-custom-terminology-applied"
GROUP = "data-plane"
SERVICES = ["translate"]


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """TranslateText with a custom terminology replaces "lighthouse" with FAROMARCADOR and reports exactly
    that terminology, with the FAROMARCADOR term, in AppliedTerminologies."""
    translate = ctx.client("translate")
    name = ctx.unique_name("sim2real-term-")
    csv_body = b"en,es\nlighthouse,FAROMARCADOR\n"
    translate.import_terminology(
        Name=name,
        MergeStrategy="OVERWRITE",
        TerminologyData={"File": csv_body, "Format": "CSV"},
        Tags=[{"Key": "project", "Value": "sim2real"}, {"Key": "owner", "Value": "behavioral-suite"}],
    )
    ctx.on_cleanup(lambda: translate.delete_terminology(Name=name))

    deadline = time.time() + 120
    resp = None
    while time.time() < deadline:
        resp = translate.translate_text(
            Text="I visited a lighthouse yesterday.",
            SourceLanguageCode="en",
            TargetLanguageCode="es",
            TerminologyNames=[name],
        )
        if resp.get("AppliedTerminologies") and "FAROMARCADOR" in resp["TranslatedText"]:
            break
        time.sleep(2)

    assert resp is not None
    translated = resp["TranslatedText"]
    assert "FAROMARCADOR" in translated, translated

    applied = resp["AppliedTerminologies"]
    assert len(applied) == 1
    assert applied[0]["Name"] == name
    terms = applied[0]["Terms"]
    assert any(t["TargetText"] == "FAROMARCADOR" for t in terms)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
