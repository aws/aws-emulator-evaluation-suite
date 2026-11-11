"""calculate-routes-unsupported-language-triggers-fallback-notice."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "calculate-routes-unsupported-language-triggers-fallback-notice"
GROUP = "data-plane"
SERVICES = ["geo-routes"]

ORIGIN = [-122.3410, 47.6089]
DESTINATION = [-122.3088, 47.4502]


@tags("axis:happy-path", "cap:unclassified", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """CalculateRoutes with Languages es-ES returns es-ES instructions and no MainLanguageNotFound notice,
    while the undetermined tag 'qqq' still routes, falling back to en-us instructions with notices of only
    Code and Impact.
    """
    client = ctx.client("geo-routes")

    supported = client.calculate_routes(
        Origin=ORIGIN, Destination=DESTINATION, Languages=["es-ES"],
        LegAdditionalFeatures=["TravelStepInstructions"],
    )
    supported_codes = {n["Code"] for n in supported["Notices"]}
    assert "MainLanguageNotFound" not in supported_codes, (
        f"a recognized language must not report MainLanguageNotFound, got notices={supported['Notices']}"
    )
    assert len(supported["Routes"]) >= 1, "expected at least one route for a recognized language"
    supported_leg = supported["Routes"][0]["Legs"][0]
    assert supported_leg["Language"].lower() == "es-es", (
        f"expected the leg to report the requested language es-es, got {supported_leg['Language']!r}"
    )
    supported_instruction = supported_leg["VehicleLegDetails"]["TravelSteps"][0]["Instruction"]
    assert any(ord(c) >= 128 for c in supported_instruction), (
        f"expected a Spanish step instruction (accented characters), got {supported_instruction!r}"
    )

    unsupported = client.calculate_routes(
        Origin=ORIGIN, Destination=DESTINATION, Languages=["qqq"],
        LegAdditionalFeatures=["TravelStepInstructions"],
    )
    assert len(unsupported["Routes"]) >= 1, "expected a valid route even for an unsupported language tag"
    unsupported_leg = unsupported["Routes"][0]["Legs"][0]
    fallback_language = unsupported_leg["Language"].lower()
    assert fallback_language != "qqq", (
        f"the reserved tag qqq must never be echoed back as the leg's Language, got {fallback_language!r}"
    )
    assert fallback_language == "en-us", (
        f"expected the undetermined-language tag to fall back to en-us, got {fallback_language!r}"
    )
    unsupported_instruction = unsupported_leg["VehicleLegDetails"]["TravelSteps"][0]["Instruction"]
    assert all(ord(c) < 128 for c in unsupported_instruction), (
        f"expected the fallback instruction text to be plain-ASCII English, not Spanish, got {unsupported_instruction!r}"
    )
    assert unsupported_instruction != supported_instruction, (
        "the fallback-language instruction must not be byte-identical to the Spanish one"
    )

    for notice in unsupported["Notices"]:
        assert set(notice) <= {"Code", "Impact"}, (
            f"RouteResponseNotice only defines Code/Impact per the geo-routes model, got keys={list(notice)}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)

