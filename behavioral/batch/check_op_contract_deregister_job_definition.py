"""op-contract-deregisterJobDefinition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-deregisterJobDefinition"
GROUP = "error-semantics"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterJobDefinition flips a revision's status from ACTIVE to INACTIVE; deregistering
    a nonexistent revision of the same name is an idempotent no-op that leaves the real
    revision untouched and creates nothing."""
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jd-")
    reg = batch.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
            "command": ["sleep", "30"],
            "resourceRequirements": [{"type": "VCPU", "value": "1"}, {"type": "MEMORY", "value": "512"}],
        },
        tags={"owner": "sim2real"},
    )
    jd_arn = reg["jobDefinitionArn"]
    revision = reg["revision"]
    # Deregistration is the only teardown a job definition has (revisions are never truly
    # removed, they go INACTIVE); the check itself already deregisters jd_arn on the success
    # path below, so this is a no-op safety net if the body raises before reaching it.
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=jd_arn))

    before = batch.describe_job_definitions(jobDefinitionName=name, status="ACTIVE")["jobDefinitions"]
    assert len(before) == 1 and before[0]["revision"] == revision and before[0]["status"] == "ACTIVE", (
        f"expected exactly one ACTIVE job definition at revision {revision}, got {before}"
    )

    # Error boundary: DeregisterJobDefinition on a nonexistent revision of the same name is
    # treated as an idempotent no-op by the real service (it does not raise), so we assert
    # the actual contract: the call succeeds without effect and creates nothing.
    fake_revision = revision + 999
    batch.deregister_job_definition(jobDefinition=f"{name}:{fake_revision}")
    unaffected = batch.describe_job_definitions(jobDefinitions=[jd_arn])["jobDefinitions"]
    assert unaffected[0]["status"] == "ACTIVE", "the real revision must be unaffected by the no-op call"
    # DescribeJobDefinitions has no "revision" filter parameter; filter client-side instead.
    all_revisions = batch.describe_job_definitions(jobDefinitionName=name)["jobDefinitions"]
    still_missing = [d for d in all_revisions if d["revision"] == fake_revision]
    assert still_missing == [], "no job definition should exist for the nonexistent revision"

    # Success path: deregistering the real revision flips it to INACTIVE.
    batch.deregister_job_definition(jobDefinition=jd_arn)
    after = batch.describe_job_definitions(jobDefinitions=[jd_arn])["jobDefinitions"]
    assert len(after) == 1 and after[0]["status"] == "INACTIVE", (
        f"expected the real revision to be INACTIVE after deregister, got {after}"
    )
    still_active = batch.describe_job_definitions(jobDefinitionName=name, status="ACTIVE")["jobDefinitions"]
    assert still_active == [], "INACTIVE revision must not show up under the ACTIVE filter"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)

