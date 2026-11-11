"""validate-pipeline-reports-errors-for-invalid-config."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "validate-pipeline-reports-errors-for-invalid-config"
GROUP = "validation"
SERVICES = ["osis"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ValidatePipeline answers a configuration with an unsupported source plugin with isValid false and exactly
    one error naming the unsupported source, a 200 response rather than ValidationException, while a valid
    configuration returns isValid true.
    """
    osis = ctx.client("osis")
    good_config = """version: "2"
osis-behav-pipeline:
  source:
    http:
      path: "/ingest"
  sink:
    - s3:
        bucket: "placeholder-bucket-name"
        codec:
          ndjson:
        aws:
          sts_role_arn: "arn:aws:iam::123456789012:role/placeholder-pipeline-role"
          region: "us-east-1"
        threshold:
          event_count: 1
          maximum_size: "1mb"
          event_collect_timeout: "60s"
"""
    good_resp = osis.validate_pipeline(PipelineConfigurationBody=good_config)
    assert good_resp["isValid"] is True, (
        f"positive control: expected isValid=True for a structurally valid config, "
        f"got errors: {good_resp.get('Errors')}"
    )

    bad_config = """version: "2"
osis-behav-pipeline:
  source:
    not-a-real-source-plugin:
      path: "/ingest"
  sink:
    - s3:
        bucket: "placeholder-bucket-name"
        region: "us-east-1"
        codec:
          ndjson:
        aws:
          sts_role_arn: "arn:aws:iam::123456789012:role/placeholder-pipeline-role"
          region: "us-east-1"
        threshold:
          event_count: 1
          maximum_size: "1mb"
          event_collect_timeout: "60s"
"""
    resp = osis.validate_pipeline(PipelineConfigurationBody=bad_config)
    assert resp["isValid"] is False, "expected isValid=False for an unsupported source plugin"
    errors = resp.get("Errors") or []
    assert len(errors) == 1, f"expected exactly one validation error (the bad source), got: {errors}"
    message = errors[0].get("Message") or ""
    assert "not in the list of sources supported" in message and "'source'" in message, (
        f"expected an error naming the unsupported-source JSON path, got: {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
