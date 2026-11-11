"""concurrent-task-definition-registration."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-task-definition-registration"
GROUP = 'concurrency'
SERVICES = ['ecs']


def _run_concurrent(fns, *, timeout_s=60):
    import concurrent.futures
    results = [None] * len(fns)
    resolved = set()

    def _capture(fut, idx):
        try:
            results[idx] = fut.result()
        except Exception as exc:
            results[idx] = exc
        resolved.add(idx)
    ex = concurrent.futures.ThreadPoolExecutor(max_workers=max(1, len(fns)))
    try:
        future_to_idx = {ex.submit(fn): i for i, fn in enumerate(fns)}
        try:
            for fut in concurrent.futures.as_completed(future_to_idx, timeout=timeout_s):
                _capture(fut, future_to_idx[fut])
        except concurrent.futures.TimeoutError as timeout_exc:
            for fut, idx in future_to_idx.items():
                if idx in resolved:
                    continue
                if fut.done():
                    _capture(fut, idx)
                else:
                    fut.cancel()
                    results[idx] = timeout_exc
    finally:
        ex.shutdown(wait=False, cancel_futures=True)
    return results


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


def _cleanup_family(ecs, family):
    arns = []
    for page in ecs.get_paginator("list_task_definitions").paginate(familyPrefix=family):
        arns.extend(page.get("taskDefinitionArns", []))
    for a in arns:
        _retire_task_definition(ecs, a)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent RegisterTaskDefinition calls for one family each get a distinct revision or a
    documented "too many concurrent attempts" rejection: never a duplicate revision number."""
    ecs = ctx.client("ecs")
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-race-")
    ctx.on_cleanup(lambda: _cleanup_family(ecs, family))

    def _container_defs():
        return [
            {
                "name": "app",
                "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
                "cpu": 64,
                "memory": 128,
                "essential": True,
            }
        ]

    # Pre-register revision 1 SEQUENTIALLY first, to unambiguously establish
    # this brand-new family as a regular (non-daemon) task-definition family
    # before racing subsequent revisions against it.
    first = ecs.register_task_definition(family=family, containerDefinitions=_container_defs())[
        "taskDefinition"
    ]
    assert first["revision"] == 1, f"expected the first registration to be revision 1, got {first}"

    n = 5

    def _register():
        return ecs.register_task_definition(family=family, containerDefinitions=_container_defs())

    results = _run_concurrent([_register for _ in range(n)], timeout_s=60)

    revisions = {1}
    for r in results:
        if isinstance(r, BaseException):
            code = _concurrent_error_codes([r])[0]
            assert code == "ClientException" and "concurrent attempts" in str(r).lower(), (
                f"expected a losing racer to fail ONLY with the documented 'too many concurrent "
                f"attempts' ClientException, got {code}: {r}"
            )
            message = r.response["Error"]["Message"]
            assert message == "Too many concurrent attempts to create a new revision of the specified family.", (
                f"expected the concurrent-revision refusal message, got {message!r}"
            )
            continue
        rev = r["taskDefinition"]["revision"]
        assert rev not in revisions, (
            f"expected every successful concurrent registration to get a DISTINCT revision number, "
            f"but {rev} was handed out more than once — a real duplicate/lost-update bug"
        )
        revisions.add(rev)

    assert len(revisions) >= 2, (
        f"expected AT LEAST ONE of the {n} concurrent racers to succeed with a new distinct "
        f"revision beyond the pre-registered rev 1, got revisions={sorted(revisions)}"
    )

    listed = ecs.list_task_definitions(familyPrefix=family, sort="ASC")["taskDefinitionArns"]
    listed_revisions = [int(arn.rsplit(":", 1)[1]) for arn in listed]
    assert sorted(set(listed_revisions)) == sorted(revisions), (
        f"expected ListTaskDefinitions to enumerate EXACTLY the successfully-registered revisions "
        f"{sorted(revisions)} (no more, no less — no phantom/duplicate entries), got {listed_revisions}"
    )

    raced_rev = max(revisions)
    raced_arn = next(a for a in listed if int(a.rsplit(":", 1)[1]) == raced_rev)
    described = ecs.describe_task_definition(taskDefinition=raced_arn)["taskDefinition"]
    assert described["revision"] == raced_rev, (
        f"expected DescribeTaskDefinition to resolve a concurrently-raced revision's ARN back to "
        f"itself, got {described['revision']}"
    )


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
