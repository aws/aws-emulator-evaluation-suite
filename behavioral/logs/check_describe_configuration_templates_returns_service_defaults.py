"""describe-configuration-templates-returns-service-defaults."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-configuration-templates-returns-service-defaults"
GROUP = "server-side"
SERVICES = ["logs"]

_VALID_DESTINATION_TYPES = {"S3", "CWL", "FH", "XRAY"}


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeConfigurationTemplates returns the fixed, service-managed catalog of
    delivery/config templates: identical across repeated calls and filterable only as a
    read-only view over static data, not user-mutable state."""
    logs = ctx.client("logs")

    resp1 = logs.describe_configuration_templates()
    templates1 = resp1["configurationTemplates"]
    assert len(templates1) > 0, "expected at least one service-managed configuration template"

    # every template must describe one of the known fixed delivery destination types
    for tmpl in templates1:
        assert tmpl["deliveryDestinationType"] in _VALID_DESTINATION_TYPES, tmpl
        assert tmpl.get("service"), f"template missing non-empty service: {tmpl}"
        assert tmpl.get("logType"), f"template missing non-empty logType: {tmpl}"

    # the catalog is server-managed and deterministic: an identical repeated call (there is
    # no Put/Update API for configuration templates) must return the exact same fixed set
    resp2 = logs.describe_configuration_templates()
    templates2 = resp2["configurationTemplates"]
    assert templates1 == templates2, "configuration templates changed between identical calls"

    # filtering narrows to a strict, consistent subset of that same fixed catalog rather than
    # generating or mutating anything -- every filtered row must appear verbatim in the
    # unfiltered set
    sample = templates1[0]
    service_name = sample["service"]
    filtered = logs.describe_configuration_templates(service=service_name)[
        "configurationTemplates"
    ]
    assert len(filtered) >= 1, f"expected service={service_name!r} filter to return at least one template"
    assert all(t["service"] == service_name for t in filtered), (
        f"service={service_name!r} filter returned a template for a different service: {filtered}"
    )
    for t in filtered:
        assert t in templates1, f"filtered template not present in full catalog: {t}"

    # filtering by an unsupported/bogus service returns an empty, well-formed list rather than
    # inventing a template or erroring
    bogus = logs.describe_configuration_templates(service="sim2real-nonexistent-service")[
        "configurationTemplates"
    ]
    assert bogus == [], f"expected no templates for a nonexistent service, got: {bogus}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
