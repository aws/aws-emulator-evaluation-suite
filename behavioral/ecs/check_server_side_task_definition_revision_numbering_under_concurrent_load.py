"""server-side-task-definition-revision-numbering-under-concurrent-load."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "server-side-task-definition-revision-numbering-under-concurrent-load"
GROUP = "server-side"
SERVICES = ["ecs"]

_TAGS = [{"key": "sim2real:managed", "value": "true"}]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent RegisterTaskDefinition calls for one family yield gap-free, unique revisions.

    ECS refuses excess in-flight callers with "Too many concurrent attempts"; callers retry on it.
    """
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-ecs-revrace-")
    concurrency = 5

    # Create the family (revision 1) before racing, so concurrent calls only race on
    # revision numbering, not on family creation.
    seed = _register_with_retry(ecs, family, "seed")
    ctx.on_cleanup(lambda: _safe_deregister(ecs, seed["taskDefinitionArn"]))
    assert seed["revision"] == 1, f"expected the first registration in a brand-new family to be revision 1, got {seed['revision']}"

    def _register(i: int) -> dict:
        return _register_with_retry(ecs, family, i)

    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(_register, range(concurrency)))

    arns = [r["taskDefinitionArn"] for r in results]
    ctx.on_cleanup(lambda arns=arns: [_safe_deregister(ecs, a) for a in arns])

    revisions = sorted(r["revision"] for r in results)
    assert revisions == list(range(2, concurrency + 2)), (
        f"expected gap-free, non-duplicated revisions 2..{concurrency + 1} under concurrent "
        f"registration (after seed revision 1), got {revisions}"
    )
    assert len(set(arns)) == concurrency, "duplicate task definition ARNs assigned under concurrent registration"

    # Cross-check the server-side record for each revision independently agrees with
    # what RegisterTaskDefinition itself returned (not just an in-memory client view).
    for r in results:
        described = ecs.describe_task_definition(taskDefinition=r["taskDefinitionArn"])["taskDefinition"]
        assert described["revision"] == r["revision"], (
            f"independent DescribeTaskDefinition disagrees with RegisterTaskDefinition's own "
            f"response: expected revision {r['revision']}, got {described['revision']}"
        )
        assert described["family"] == family, f"expected family {family!r}, got {described['family']!r}"
        assert described["taskDefinitionArn"] == r["taskDefinitionArn"], (
            f"expected ARN {r['taskDefinitionArn']!r}, got {described['taskDefinitionArn']!r}"
        )

    # A subsequent registration must continue the sequence (no reuse/rewind of numbers).
    followup = ecs.register_task_definition(
        family=family,
        containerDefinitions=[
            {"name": "main", "image": "busybox:1.36", "cpu": 64, "memory": 64, "essential": True}
        ],
        tags=_TAGS,
    )["taskDefinition"]
    ctx.on_cleanup(lambda: _safe_deregister(ecs, followup["taskDefinitionArn"]))
    expected_followup_revision = concurrency + 2
    assert followup["revision"] == expected_followup_revision, (
        f"expected the sequence to continue gap-free after the concurrent batch: "
        f"revision {expected_followup_revision}, got {followup['revision']}"
    )
    described_followup = ecs.describe_task_definition(taskDefinition=followup["taskDefinitionArn"])["taskDefinition"]
    assert described_followup["revision"] == expected_followup_revision, (
        f"independent DescribeTaskDefinition disagrees with the follow-up registration: "
        f"expected revision {expected_followup_revision}, got {described_followup['revision']}"
    )



# ===== helpers =====

def _register_with_retry(ecs, family: str, i: int, max_attempts: int = 15) -> dict:
    """RegisterTaskDefinition on a family under high concurrency: retry ONLY on the
    named "too many concurrent attempts" ClientException (a real, documented ECS
    concurrency bound), and re-raise anything else immediately."""
    delay = 0.4
    last_exc: Exception | None = None
    for _attempt in range(max_attempts):
        try:
            return ecs.register_task_definition(
                family=family,
                containerDefinitions=[
                    {
                        "name": "main",
                        "image": "busybox:1.36",
                        "cpu": 64,
                        "memory": 64,
                        "essential": True,
                        "command": ["echo", str(i)],
                    }
                ],
                tags=_TAGS,
            )["taskDefinition"]
        except ecs.exceptions.ClientException as e:
            if "too many concurrent attempts" in str(e).lower():
                last_exc = e
                time.sleep(delay)
                delay = min(delay * 1.7, 5.0)
                continue
            raise
    raise AssertionError(
        f"gave up after {max_attempts} attempts registering revision {i} due to "
        f"repeated concurrency throttling: {last_exc}"
    )


def _safe_deregister(ecs, arn: str) -> None:
    _retire_task_definition(ecs, arn)


def _retire_task_definition(ecs, task_definition: str) -> None:
    """Deregister a task definition revision, then delete it: a deregistered revision stays
    INACTIVE until DeleteTaskDefinitions removes it. An already-deleted revision is fine; any
    other failure raises."""
    from botocore.exceptions import ClientError

    try:
        described = ecs.describe_task_definition(taskDefinition=task_definition)["taskDefinition"]
    except ClientError as exc:
        if "Unable to describe task definition" in exc.response["Error"].get("Message", ""):
            return
        raise
    arn = described["taskDefinitionArn"]
    if described["status"] == "DELETE_IN_PROGRESS":
        return
    if described["status"] == "ACTIVE":
        ecs.deregister_task_definition(taskDefinition=arn)
    failures = ecs.delete_task_definitions(taskDefinitions=[arn]).get("failures", [])
    if failures:
        raise RuntimeError(f"task definition {arn} teardown failed: {failures}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
