"""get-log-fields-nonexistent-group-succeeds."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-log-fields-nonexistent-group-succeeds"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetLogFields for two nonexistent data source names succeeds and returns the same non-empty list of
    field names and types for the data source type.
    """
    logs = ctx.client("logs")
    bogus_name_a = ctx.unique_name("sim2real-nonexistent-datasource-a-")
    bogus_name_b = ctx.unique_name("sim2real-nonexistent-datasource-b-")

    resp_a = logs.get_log_fields(dataSourceName=bogus_name_a, dataSourceType="AWSLogs")
    resp_b = logs.get_log_fields(dataSourceName=bogus_name_b, dataSourceType="AWSLogs")
    fields_a = resp_a.get("logFields", [])
    fields_b = resp_b.get("logFields", [])

    assert fields_a, "expected the call to succeed with AWSLogs's fixed field schema, got no fields"
    for field in fields_a:
        assert "logFieldName" in field and "logFieldType" in field, field

    assert fields_a == fields_b, (
        f"expected the AWSLogs field schema to be independent of the (nonexistent) data source "
        f"name, got {fields_a!r} vs {fields_b!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
