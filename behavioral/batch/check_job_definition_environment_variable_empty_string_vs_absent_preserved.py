"""job-definition-environment-variable-empty-string-vs-absent-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "job-definition-environment-variable-empty-string-vs-absent-preserved"
GROUP = "representation"
SERVICES = ["batch"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """An explicit empty-string container env var is dropped on RegisterJobDefinition, so it reads
    back exactly like a name never set, while a non-empty env var round-trips unchanged.
    """
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-batch-jd-envvar-")

    reg = batch.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": "public.ecr.aws/docker/library/busybox:1.36",
            "command": ["echo", "hello"],
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "512"},
            ],
            "environment": [
                {"name": "EMPTY_VAR", "value": ""},
                {"name": "PRESENT_VAR", "value": "hello-world"},
            ],
        },
    )
    revision = reg["revision"]
    job_def_arn = reg["jobDefinitionArn"]
    ctx.on_cleanup(
        lambda: batch.deregister_job_definition(jobDefinition=job_def_arn)
    )

    described = batch.describe_job_definitions(jobDefinitionName=name, status="ACTIVE")
    matches = [jd for jd in described["jobDefinitions"] if jd["revision"] == revision]
    assert len(matches) == 1, f"expected exactly one matching revision, got {matches}"
    env_list = matches[0]["containerProperties"]["environment"]
    env_by_name = {e["name"]: e["value"] for e in env_list}

    assert "EMPTY_VAR" not in env_by_name, (
        f"expected real AWS to silently drop the explicit empty-string env var, "
        f"but it was present: {env_by_name.get('EMPTY_VAR')!r}"
    )
    assert env_by_name.get("PRESENT_VAR") == "hello-world", (
        "a normal non-empty env var value did not survive the round-trip unchanged"
    )
    assert "ABSENT_VAR" not in env_by_name, "a never-mentioned env var name materialized"
    # Real AWS accepts the empty-string entry but never echoes it back, so it is
    # indistinguishable from a name that was never mentioned.
    assert ("EMPTY_VAR" in env_by_name) == ("ABSENT_VAR" in env_by_name), (
        f"expected EMPTY_VAR's absence to match ABSENT_VAR's, got env_by_name={env_by_name!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
