"""configuration-templates-are-server-managed-static."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "configuration-templates-are-server-managed-static"
GROUP = "server-side"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeConfigurationTemplates returns well-formed AWS-managed templates, a deliveryDestinationTypes
    filter returns only that type, and a repeated call returns identical templates."""
    logs = ctx.client("logs")

    first = logs.describe_configuration_templates()
    templates = first["configurationTemplates"]
    assert templates, "expected at least one AWS-managed configuration template"

    valid_destination_types = {"S3", "CWL", "FH", "XRAY"}
    for template in templates:
        assert template["deliveryDestinationType"] in valid_destination_types, template
        assert isinstance(template.get("logType"), str) and template["logType"], (
            f"expected a non-empty string logType, got {template.get('logType')!r}"
        )
        assert isinstance(template.get("service"), str) and template["service"], (
            f"expected a non-empty string service, got {template.get('service')!r}"
        )

    # Filtering by a delivery destination type present in the first response
    # must deterministically narrow the results to only that type -- this is
    # server-managed reference data, not a mutable user resource.
    some_type = templates[0]["deliveryDestinationType"]
    filtered = logs.describe_configuration_templates(deliveryDestinationTypes=[some_type])
    assert filtered["configurationTemplates"], "filter should still return at least one template"
    for template in filtered["configurationTemplates"]:
        assert template["deliveryDestinationType"] == some_type, (
            f"filter for {some_type!r} leaked a template of type "
            f"{template['deliveryDestinationType']!r}"
        )

    # Calling again with no filter is idempotent / deterministic: AWS
    # returns the exact same list, in the same order, for this server-managed
    # catalog.
    second = logs.describe_configuration_templates()
    assert templates == second["configurationTemplates"], (
        "configuration templates changed between identical calls"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
