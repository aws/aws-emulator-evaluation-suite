"""jd-deregister-sets-inactive-and-is-idempotent."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "jd-deregister-sets-inactive-and-is-idempotent"
GROUP = 'job-definition'
SERVICES = ['batch']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterJobDefinition marks the revision INACTIVE; calling it twice is idempotent."""
    batch = ctx.client("batch")
    name, revision, _arn = _register_basic_job_definition(ctx)
    ref = f"{name}:{revision}"

    batch.deregister_job_definition(jobDefinition=ref)
    resp = batch.describe_job_definitions(jobDefinitions=[ref])
    defs = resp["jobDefinitions"]
    assert len(defs) == 1 and defs[0]["status"] == "INACTIVE", "expected job definition to be INACTIVE"
    arn = defs[0]["jobDefinitionArn"]

    # second deregister of an already-inactive definition must be a genuine no-op: it must not
    # raise, AND an independent read afterward must show the same single INACTIVE revision with
    # its identity unchanged (idempotent means "no additional effect", not just "did not raise").
    batch.deregister_job_definition(jobDefinition=ref)
    resp2 = batch.describe_job_definitions(jobDefinitions=[ref])
    defs2 = resp2["jobDefinitions"]
    assert (
        len(defs2) == 1 and defs2[0]["status"] == "INACTIVE" and defs2[0]["jobDefinitionArn"] == arn
    ), f"expected repeated deregister to be a no-op, got {defs2}"


def _register_basic_job_definition(ctx, command: list[str] | None = None):
    """A minimal container job definition. Returns (name, revision, arn).

    Deregistration is the only teardown a job definition has (revisions are
    never truly removed, they go INACTIVE), and it is idempotent — which is
    exactly what this check exercises — so registering the cleanup up front is
    safe even though the check deregisters the same ref itself.
    """
    batch = ctx.client("batch")
    name = ctx.unique_name("sim2real-behav-batch-jd-")
    resp = batch.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": "busybox:1.36",
            "vcpus": 1,
            "memory": 128,
            "command": command or ["echo", "hello"],
        },
    )
    revision = resp["revision"]
    ref = f"{name}:{revision}"
    ctx.on_cleanup(lambda: batch.deregister_job_definition(jobDefinition=ref))
    return name, revision, resp["jobDefinitionArn"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
