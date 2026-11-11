"""detect-pii-entities-unsupported-language-still-succeeds."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "detect-pii-entities-unsupported-language-still-succeeds"
GROUP = "error-semantics"
SERVICES = ["comprehend"]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DetectPiiEntities with LanguageCode "es" is not rejected as unsupported: it still finds the EMAIL
    entity in the text, like the "en" control call."""
    comprehend = ctx.client("comprehend")
    text = "Please contact John at john.doe@example.com for the invoice."

    # Positive control: English is unambiguously supported for PII detection.
    ok_resp = comprehend.detect_pii_entities(Text=text, LanguageCode="en")
    assert ok_resp["Entities"], "expected the positive control to find PII entities"

    # LanguageCode="es" is a valid LanguageCode enum member; the real service still accepts it
    # and still finds the language-agnostic email entity, rather than raising an error.
    es_resp = comprehend.detect_pii_entities(Text=text, LanguageCode="es")
    assert es_resp["Entities"], f"expected 'es' request to still find PII entities: {es_resp}"
    assert any(e["Type"] == "EMAIL" for e in es_resp["Entities"]), es_resp["Entities"]


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

