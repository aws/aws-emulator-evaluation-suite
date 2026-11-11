"""deregister-job-definition-marks-inactive."""

from __future__ import annotations
import time

from behavioral_harness import tags


CHECK = "deregister-job-definition-marks-inactive"
GROUP = 'job-definition'
SERVICES = ['batch']

def _swallow(fn):
    """Run a teardown step; any failure raises."""
    fn()


def _poll_until(probe, predicate, *, timeout_s=60, interval_s=1.0, description="condition"):
    """Poll probe() until predicate(result) is truthy; return the final result."""
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not met within {timeout_s}s. Last result: {last!r}")


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
    )
    rev = resp["revision"]
    ctx.on_cleanup(lambda: _deregister_jd(bat, name, rev))
    return name, resp["jobDefinitionArn"], rev


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeregisterJobDefinition transitions a revision ACTIVE -> INACTIVE; it is not deleted
    outright, and a repeated call on an already-INACTIVE revision is idempotent."""
    bat = ctx.client("batch")
    name, arn, revision = _register_job_definition(ctx, bat)

    before = _describe_job_definition(bat, name, revision=revision)
    assert before is not None and before["status"] == "ACTIVE", (
        f"expected freshly registered revision ACTIVE, got {before!r}"
    )

    bat.deregister_job_definition(jobDefinition=f"{name}:{revision}")
    d = _poll_until(lambda: _describe_job_definition(bat, name, revision=revision), lambda d: d is not None and d.get("status") == "INACTIVE", timeout_s=60, interval_s=3, description="job definition INACTIVE")
    assert d["status"] == "INACTIVE", f"expected INACTIVE after deregister, got {d['status']!r}"
    assert d["jobDefinitionArn"] == arn, f"expected arn {arn!r}, got {d['jobDefinitionArn']!r}"

    # A second deregister of an already-inactive definition must be an idempotent no-op.
    bat.deregister_job_definition(jobDefinition=f"{name}:{revision}")
    d2 = _describe_job_definition(bat, name, revision=revision)
    assert d2 is not None and d2["status"] == "INACTIVE", (
        f"repeated DeregisterJobDefinition must be a no-op leaving the revision INACTIVE, got {d2!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
