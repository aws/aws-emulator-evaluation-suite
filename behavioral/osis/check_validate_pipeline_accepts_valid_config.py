"""validate-pipeline-accepts-valid-config."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "validate-pipeline-accepts-valid-config"
GROUP = "validation"
SERVICES = ["osis"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ValidatePipeline reports isValid=True and no errors for a structurally valid
    Data Prepper pipeline configuration (http source -> s3 sink), without provisioning
    anything -- it is a pure static/schema check."""
    osis = ctx.client("osis")
    config = """version: "2"
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
    resp = osis.validate_pipeline(PipelineConfigurationBody=config)
    assert resp["isValid"] is True, f"expected isValid=True, got errors: {resp.get('Errors')}"
    assert not resp.get("Errors"), f"expected no validation errors, got: {resp.get('Errors')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
