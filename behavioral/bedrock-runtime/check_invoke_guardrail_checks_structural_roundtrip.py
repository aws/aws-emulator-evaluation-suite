"""invoke-guardrail-checks-structural-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "invoke-guardrail-checks-structural-roundtrip"
GROUP = "data-plane"
SERVICES = ["bedrock-runtime"]


@tags("axis:happy-path", "cap:c7", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """InvokeGuardrailChecks scores exactly the requested categories in [0.0, 1.0], and a threat of
    violence scores non-zero on VIOLENCE and higher than benign text, so scores depend on the text.
    """
    brt = ctx.client("bedrock-runtime")
    checks = {
        "contentFilter": {
            "categories": [{"category": "VIOLENCE"}, {"category": "HATE"}]
        }
    }

    resp = brt.invoke_guardrail_checks(
        messages=[{"role": "user", "content": [{"text": "I am going to hurt you badly."}]}],
        checks=checks,
    )
    results = resp["results"]["contentFilter"]["results"]
    categories_seen = {r["category"] for r in results}
    assert categories_seen == {"VIOLENCE", "HATE"}, (
        f"requested categories were VIOLENCE, HATE; results carried {sorted(categories_seen)!r}"
    )
    scores = {r["category"]: r["severityScore"] for r in results}
    for category, score in scores.items():
        assert 0.0 <= score <= 1.0, f"{category} severityScore {score!r} outside [0.0, 1.0]"
    assert scores["VIOLENCE"] > 0.0, (
        f"an explicit threat of violence scored zero on VIOLENCE: {scores!r}"
    )

    benign = brt.invoke_guardrail_checks(
        messages=[{"role": "user", "content": [{"text": "Hello, how has your day been?"}]}],
        checks=checks,
    )
    benign_scores = {
        r["category"]: r["severityScore"]
        for r in benign["results"]["contentFilter"]["results"]
    }
    assert set(benign_scores) == {"VIOLENCE", "HATE"}, (
        f"requested categories were VIOLENCE, HATE; results carried {sorted(benign_scores)!r}"
    )
    assert benign_scores["VIOLENCE"] < scores["VIOLENCE"], (
        f"benign text scored VIOLENCE {benign_scores['VIOLENCE']!r}, not lower than the "
        f"explicit threat's {scores['VIOLENCE']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
