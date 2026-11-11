"""jd-describe-filters-by-status."""

from __future__ import annotations

from behavioral_harness import tags


CHECK = "jd-describe-filters-by-status"
GROUP = 'job-definition'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    fn()


def _deregister_jd(bat, name, revision):
    _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{revision}"))


def _register_basic_job_definition(ctx, bat, name=None, command=None):
    name = name or ctx.unique_name("sim2real-behav-jd-")
    resp = bat.register_job_definition(
        jobDefinitionName=name,
        type="container",
        containerProperties={
            "image": "busybox:1.36",
            "vcpus": 1,
            "memory": 128,
            "command": command or ["echo", "hello"],
        },
        tags=_MANAGED_TAGS,
    )
    revision = resp["revision"]
    ctx.on_cleanup(lambda: _deregister_jd(bat, name, revision))
    return name, revision, resp["jobDefinitionArn"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeJobDefinitions status filter separates ACTIVE from INACTIVE revisions."""
    bat = ctx.client("batch")
    name, revision, _arn = _register_basic_job_definition(ctx, bat)

    active = bat.describe_job_definitions(jobDefinitionName=name, status="ACTIVE")["jobDefinitions"]
    assert any(d["revision"] == revision for d in active), "freshly registered revision should be ACTIVE"

    bat.deregister_job_definition(jobDefinition=f"{name}:{revision}")

    active_after = bat.describe_job_definitions(jobDefinitionName=name, status="ACTIVE")["jobDefinitions"]
    assert all(d["revision"] != revision for d in active_after), "deregistered revision must not show as ACTIVE"

    inactive_after = bat.describe_job_definitions(jobDefinitionName=name, status="INACTIVE")["jobDefinitions"]
    assert any(d["revision"] == revision for d in inactive_after), "deregistered revision should show as INACTIVE"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
