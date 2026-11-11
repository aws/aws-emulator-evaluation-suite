"""register-job-definition-revision-increment."""

from __future__ import annotations

from behavioral_harness import tags


CHECK = "register-job-definition-revision-increment"
GROUP = 'job-definition'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _swallow(fn):
    """Run a teardown step; any failure raises."""
    fn()


def _describe_job_definition(bat, name, revision=None):
    defs = bat.describe_job_definitions(jobDefinitionName=name).get("jobDefinitions", [])
    if revision is not None:
        defs = [d for d in defs if d.get("revision") == revision]
    return defs[0] if defs else None


def _deregister_jd(bat, name, revision):
    _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{revision}"))


def _register_job_definition(ctx, bat, name=None, command=None):
    name = name or ctx.unique_name("sim2real-behav-jd-")
    resp = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": "busybox:1.36",
            "command": command or ["echo", "hello"],
            "resourceRequirements": [
                {"type": "VCPU", "value": "1"},
                {"type": "MEMORY", "value": "512"},
            ],
        },
        tags=dict(_MANAGED_TAGS),
    )
    rev = resp["revision"]
    ctx.on_cleanup(lambda: _deregister_jd(bat, name, rev))
    return name, resp["jobDefinitionArn"], rev


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Re-registering the same job definition name creates a new, monotonically increasing revision."""
    bat = ctx.client("batch")
    name = ctx.unique_name("sim2real-behav-" + "jd-rev-")
    _, arn1, rev1 = _register_job_definition(ctx, bat, name=name)
    _, arn2, rev2 = _register_job_definition(ctx, bat, name=name)

    assert rev2 == rev1 + 1, f"expected revision to increment by 1, got {rev1} -> {rev2}"
    assert arn1 != arn2, f"expected distinct ARNs for distinct revisions, got {arn1!r} twice"

    d1 = _describe_job_definition(bat, name, revision=rev1)
    d2 = _describe_job_definition(bat, name, revision=rev2)
    assert d1["status"] == "ACTIVE", f"expected revision {rev1} status ACTIVE, got {d1['status']!r}"
    assert d2["status"] == "ACTIVE", f"expected revision {rev2} status ACTIVE, got {d2['status']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
