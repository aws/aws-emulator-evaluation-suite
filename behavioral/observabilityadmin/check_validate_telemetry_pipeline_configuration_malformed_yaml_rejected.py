"""validate-telemetry-pipeline-configuration-malformed-yaml-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "validate-telemetry-pipeline-configuration-malformed-yaml-rejected"
GROUP = "overly-permissive"
SERVICES = ["observabilityadmin"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidateTelemetryPipelineConfiguration answers 200 with Errors for unparseable YAML (one
    PIPELINE_CONFIGURATION_PARSE_ERROR), a malformed sts_role_arn and an unknown processor, each naming
    its Reason and field, and no Errors for a valid configuration."""
    client = ctx.client("observabilityadmin")
    role_arn = "arn:aws:iam::123456789012:role/Sim2RealNonExistentPipelineRole"

    # Genuinely unparseable YAML (unterminated flow sequence) fails before schema evaluation
    # ever runs: exactly one error, with no downstream schema-mismatch cascade.
    malformed_body = "pipeline:\n  source: [unterminated\n  processor"
    resp_malformed = client.validate_telemetry_pipeline_configuration(
        Configuration={"Body": malformed_body}
    )
    malformed_errors = resp_malformed.get("Errors") or []
    assert len(malformed_errors) == 1, (
        f"expected exactly one parse error for unparseable YAML, got {malformed_errors!r}"
    )
    assert malformed_errors[0]["Reason"] == "PIPELINE_CONFIGURATION_PARSE_ERROR", (
        f"expected Reason=PIPELINE_CONFIGURATION_PARSE_ERROR for unparseable YAML, "
        f"got {malformed_errors[0]!r}"
    )

    # A syntactically valid ARN string that is not IAM-ARN-shaped is a content-level schema
    # mismatch, not a synchronous rejection -- it surfaces in the same Errors list, pinned to
    # the exact field that failed its pattern.
    bad_arn_body = _pipeline_body("not-a-valid-arn-at-all", processor="parse_json: {}")
    resp_bad_arn = client.validate_telemetry_pipeline_configuration(
        Configuration={"Body": bad_arn_body}
    )
    bad_arn_errors = resp_bad_arn.get("Errors") or []
    arn_error = next(
        (
            e
            for e in bad_arn_errors
            if e.get("Reason") == "INVALID_PATTERN"
            and e.get("FieldMap", {}).get("path", "").endswith("sts_role_arn")
        ),
        None,
    )
    assert arn_error is not None, (
        f"expected an INVALID_PATTERN error pinned to sts_role_arn, got {bad_arn_errors!r}"
    )

    # An unknown processor name is likewise a content-level schema mismatch: UNKNOWN_PROPERTY
    # pinned to the specific processor entry that named it.
    semantically_bad_body = _pipeline_body(role_arn, processor="not_a_real_processor_xyz: {}")
    resp_bad_processor = client.validate_telemetry_pipeline_configuration(
        Configuration={"Body": semantically_bad_body}
    )
    processor_errors = resp_bad_processor.get("Errors") or []
    processor_error = next(
        (
            e
            for e in processor_errors
            if e.get("Reason") == "UNKNOWN_PROPERTY"
            and "not_a_real_processor_xyz" in e.get("Message", "")
        ),
        None,
    )
    assert processor_error is not None, (
        f"expected an UNKNOWN_PROPERTY error naming the bad processor, got {processor_errors!r}"
    )

    # Positive control: a fully valid configuration reports no errors at all.
    valid_body = _pipeline_body(role_arn, processor="parse_json: {}")
    resp_good = client.validate_telemetry_pipeline_configuration(
        Configuration={"Body": valid_body}
    )
    assert not resp_good.get("Errors"), (
        f"expected no errors for a valid configuration, got {resp_good.get('Errors')!r}"
    )


def _pipeline_body(role_arn: str, processor: str) -> str:
    return (
        "pipeline:\n"
        "  source:\n"
        "    cloudwatch_logs:\n"
        "      log_event_metadata:\n"
        '        data_source_name: "sim2real_src"\n'
        '        data_source_type: "default"\n'
        "      aws:\n"
        f'        sts_role_arn: "{role_arn}"\n'
        "  processor:\n"
        f"    - {processor}\n"
        "  sink:\n"
        "    - cloudwatch_logs:\n"
        '        log_group: "@original"\n'
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
