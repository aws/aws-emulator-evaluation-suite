"""describe-configuration-templates-lists-defaults."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-configuration-templates-lists-defaults"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeConfigurationTemplates returns the service's default delivery config templates."""
    logs = ctx.client("logs")

    s3_resp = logs.describe_configuration_templates(deliveryDestinationTypes=["S3"])
    templates = s3_resp["configurationTemplates"]
    assert len(templates) > 0, "expected at least one S3 delivery configuration template"
    for tpl in templates:
        assert tpl["deliveryDestinationType"] == "S3", f"expected S3, got {tpl!r}"
        assert tpl["service"], f"expected non-empty service, got {tpl!r}"
        assert tpl["logType"], f"expected non-empty logType, got {tpl!r}"
        # allowedFields describes the valid record fields for this template's deliveries.
        assert isinstance(tpl["allowedFields"], list) and len(tpl["allowedFields"]) > 0, (
            f"expected a non-empty allowedFields list, got {tpl!r}"
        )
        for f in tpl["allowedFields"]:
            assert "name" in f and "mandatory" in f, f"expected name+mandatory keys, got {f!r}"

    cwl_resp = logs.describe_configuration_templates(deliveryDestinationTypes=["CWL"])
    cwl_templates = cwl_resp["configurationTemplates"]
    assert len(cwl_templates) > 0, "expected at least one CWL delivery configuration template"
    for tpl in cwl_templates:
        assert tpl["deliveryDestinationType"] == "CWL", f"expected CWL, got {tpl!r}"

    # The two filters must not be interchangeable: an S3 template's echoed type is never CWL.
    s3_types = {t["deliveryDestinationType"] for t in templates}
    cwl_types = {t["deliveryDestinationType"] for t in cwl_templates}
    assert s3_types == {"S3"}, f"S3 filter leaked other destination types: {s3_types!r}"
    assert cwl_types == {"CWL"}, f"CWL filter leaked other destination types: {cwl_types!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
