"""network-migration-mapping-and-analysis-without-execution-rejected."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "network-migration-mapping-and-analysis-without-execution-rejected"
GROUP = "overly-permissive"
SERVICES = ["mgn"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """StartNetworkMigrationMapping and StartNetworkMigrationAnalysis on an invented execution id fail
    with ResourceNotFoundException; on the definition's own execution, Mapping starts a job and
    Analysis fails with ConflictException while that mapping job runs.
    """
    mgn = ctx.client("mgn")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    src_bucket, src_key = _make_source_object(ctx)
    name = ctx.unique_name("sim2real-mgn-nmd-noexec-")

    created = mgn.create_network_migration_definition(
        name=name,
        sourceConfigurations=[
            {
                "sourceEnvironment": "LOGICAL_MODEL",
                "sourceS3Configuration": {
                    "s3Bucket": src_bucket,
                    "s3BucketOwner": account_id,
                    "s3Key": src_key,
                },
            }
        ],
        targetS3Configuration={"s3Bucket": src_bucket, "s3BucketOwner": account_id},
        targetNetwork={
            "topology": "ISOLATED_VPC",
            "inboundCidr": "10.0.0.0/24",
            "outboundCidr": "10.0.1.0/24",
            "inspectionCidr": "10.0.2.0/24",
        },
        tags={"sim2real-key": "sim2real-value"},
    )
    nmd_id = created["networkMigrationDefinitionID"]
    ctx.on_cleanup(lambda: mgn.delete_network_migration_definition(networkMigrationDefinitionID=nmd_id))

    # (0) Positive control: the definition auto-stages a real execution at creation time, and
    # that real id -- unlike an invented one -- is accepted by StartNetworkMigrationMapping.
    staged = mgn.list_network_migration_executions(networkMigrationDefinitionID=nmd_id)["items"]
    assert len(staged) == 1, f"expected exactly one auto-staged execution, got {staged!r}"
    real_execution_id = staged[0]["networkMigrationExecutionID"]
    assert staged[0].get("stage") == "MAPPING", f"expected the auto-staged execution at MAPPING, got {staged[0]!r}"

    real_mapping = mgn.start_network_migration_mapping(
        networkMigrationDefinitionID=nmd_id,
        networkMigrationExecutionID=real_execution_id,
        securityGroupMappingStrategy="SKIP",
    )
    real_job_id = real_mapping.get("jobID")
    assert real_job_id is not None, (
        "StartNetworkMigrationMapping against the auto-staged real execution id must start a "
        f"job (proving the id itself, not the whole pipeline, was the problem), got {real_mapping!r}"
    )

    # (0b) That same real id, one call later, is still rejected for Analysis -- but with a
    # DIFFERENT, more specific code than an unknown id gets: it exists but is in the wrong stage.
    real_analysis_code, real_analysis_message = None, None
    real_analysis_job_id = None
    try:
        real_analysis_job_id = mgn.start_network_migration_analysis(
            networkMigrationDefinitionID=nmd_id, networkMigrationExecutionID=real_execution_id
        ).get("jobID")
    except ClientError as exc:
        real_analysis_code = exc.response.get("Error", {}).get("Code")
        real_analysis_message = exc.response.get("Error", {}).get("Message")
    assert real_analysis_job_id is None, (
        "StartNetworkMigrationAnalysis must not start a job for an execution still mid-mapping, "
        f"got jobID={real_analysis_job_id!r}"
    )
    assert real_analysis_code == "ConflictException", (
        "a real, known execution id in the wrong stage must be rejected with ConflictException "
        f"(distinct from an unknown id's ResourceNotFoundException), got {real_analysis_code!r}"
    )
    busy_message = (
        "A job cannot be started because another job for this execution is currently in progress."
    )
    assert real_analysis_message == busy_message, (
        f"expected the ConflictException message {busy_message!r}, got {real_analysis_message!r}"
    )

    # (1) The pipeline's own entry point (Mapping) rejects a freshly-invented execution id.
    mapping_execution_id = str(uuid.uuid4())
    mapping_code, mapping_message = None, None
    mapping_job_id = None
    try:
        mapping_job_id = mgn.start_network_migration_mapping(
            networkMigrationDefinitionID=nmd_id,
            networkMigrationExecutionID=mapping_execution_id,
            securityGroupMappingStrategy="SKIP",
        ).get("jobID")
    except ClientError as exc:
        mapping_code = exc.response.get("Error", {}).get("Code")
        mapping_message = exc.response.get("Error", {}).get("Message")
    assert mapping_job_id is None, (
        f"StartNetworkMigrationMapping must not start a job for a caller-invented execution "
        f"id, got jobID={mapping_job_id!r}"
    )
    assert mapping_code == "ResourceNotFoundException", (
        f"StartNetworkMigrationMapping with an unregistered execution id must raise "
        f"ResourceNotFoundException, got {mapping_code!r}"
    )
    expected = f"NetworkMigrationExecution with Id: '{mapping_execution_id}' was not found"
    assert mapping_message == expected, f"expected message {expected!r}, got {mapping_message!r}"

    # (2) A later pipeline stage (Analysis) rejects an equally-fresh, never-mapped id too.
    analysis_execution_id = str(uuid.uuid4())
    analysis_code, analysis_message = None, None
    analysis_job_id = None
    try:
        analysis_job_id = mgn.start_network_migration_analysis(
            networkMigrationDefinitionID=nmd_id,
            networkMigrationExecutionID=analysis_execution_id,
        ).get("jobID")
    except ClientError as exc:
        analysis_code = exc.response.get("Error", {}).get("Code")
        analysis_message = exc.response.get("Error", {}).get("Message")
    assert analysis_job_id is None, (
        "StartNetworkMigrationAnalysis must not start a job for an execution id that was "
        f"never staged, got jobID={analysis_job_id!r}"
    )
    assert analysis_code == "ResourceNotFoundException", (
        f"StartNetworkMigrationAnalysis with an unregistered execution id must raise "
        f"ResourceNotFoundException, got {analysis_code!r}"
    )
    expected = f"NetworkMigrationExecution with Id: '{analysis_execution_id}' was not found"
    assert analysis_message == expected, f"expected message {expected!r}, got {analysis_message!r}"

    # Neither rejected invented id should have left an execution record behind.
    executions = mgn.list_network_migration_executions(networkMigrationDefinitionID=nmd_id)["items"]
    seen_ids = {e.get("networkMigrationExecutionID") for e in executions}
    assert mapping_execution_id not in seen_ids, (
        f"the rejected mapping id {mapping_execution_id!r} must not appear in {seen_ids!r}"
    )
    assert analysis_execution_id not in seen_ids, (
        f"the rejected analysis id {analysis_execution_id!r} must not appear in {seen_ids!r}"
    )

    # The real mapping job we started for the positive control must finish before teardown --
    # MGN refuses DeleteNetworkMigrationDefinition while a job on it is in flight.
    deadline = time.monotonic() + 180
    terminal = {"SUCCEEDED", "FAILED"}
    while time.monotonic() < deadline:
        jobs = mgn.list_network_migration_mappings(
            networkMigrationDefinitionID=nmd_id, networkMigrationExecutionID=real_execution_id
        )["items"]
        match = [j for j in jobs if j.get("jobID") == real_job_id]
        if match and match[0].get("status") in terminal:
            break
        time.sleep(5)
    else:
        raise AssertionError(
            f"real-id mapping job {real_job_id!r} did not reach a terminal status within 180s"
        )


def _make_source_object(ctx):
    s3 = ctx.client("s3")
    bucket = ctx.unique_name("sim2real-mgn-nmd-src-").lower()
    if ctx.region == "us-east-1":
        s3.create_bucket(Bucket=bucket)
    else:
        s3.create_bucket(Bucket=bucket, CreateBucketConfiguration={"LocationConstraint": ctx.region})
    key = "sim2real/source-model.json"
    s3.put_object(Bucket=bucket, Key=key, Body=b"{}")

    def _cleanup():
        try:
            s3.delete_object(Bucket=bucket, Key=key)
        except ClientError as exc:
            if exc.response["Error"]["Code"] not in ("NoSuchBucket", "NoSuchKey"):
                raise
        try:
            s3.delete_bucket(Bucket=bucket)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NoSuchBucket":
                raise

    ctx.on_cleanup(_cleanup)
    return bucket, key


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
