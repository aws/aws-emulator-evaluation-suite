"""concurrent-create-service-duplicate-name."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-service-duplicate-name"
GROUP = 'concurrency'
SERVICES = ['ecs']

DEFAULT_CONTAINER_DEFS = [
    {
        "name": "app",
        "image": "public.ecr.aws/amazonlinux/amazonlinux:2023",
        "cpu": 64,
        "memory": 128,
        "essential": True,
    }
]

_ECS_TAGS = [{"key": "sim2real", "value": "true"}]


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


def _concurrent_successes(results):
    return sum((1 for r in results if not isinstance(r, BaseException)))


def _concurrent_error_codes(results):
    codes = []
    for r in results:
        if isinstance(r, ClientError):
            codes.append(r.response.get('Error', {}).get('Code'))
        elif isinstance(r, BaseException):
            codes.append(type(r).__name__)
    return codes


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """N concurrent CreateService calls for the same name in one cluster resolve to exactly one
    winner: never two ACTIVE services under one name, nor a losing call reported as success."""
    ecs = ctx.client("ecs")
    name = ctx.unique_name("sim2real-behav-ecs-cluster-")
    ecs.create_cluster(clusterName=name, tags=_ECS_TAGS)
    ctx.on_cleanup(lambda: ecs.delete_cluster(cluster=name))
    family = ctx.unique_name("sim2real-behav-ecs-taskdef-")
    td = ecs.register_task_definition(
        family=family, containerDefinitions=DEFAULT_CONTAINER_DEFS, tags=_ECS_TAGS
    )["taskDefinition"]
    ctx.on_cleanup(lambda: ecs.delete_task_definitions(taskDefinitions=[td["taskDefinitionArn"]]))
    ctx.on_cleanup(lambda: ecs.deregister_task_definition(taskDefinition=td["taskDefinitionArn"]))
    svc_name = ctx.unique_name("sim2real-behav-ecs-race-svc-")
    ctx.on_cleanup(lambda: ecs.delete_service(cluster=name, service=svc_name, force=True))

    def _attempt():
        return ecs.create_service(
            cluster=name,
            serviceName=svc_name,
            taskDefinition=td["taskDefinitionArn"],
            desiredCount=0,
            tags=_ECS_TAGS,
        )

    results = _run_concurrent([_attempt for _ in range(5)], timeout_s=60)
    successes = _concurrent_successes(results)
    assert successes == 1, (
        f"expected EXACTLY ONE winner racing to create service {svc_name!r}, got {successes} successes "
        f"(codes: {_concurrent_error_codes(results)})"
    )
    error_codes = _concurrent_error_codes(results)
    assert all(c == "InvalidParameterException" for c in error_codes), (
        f"expected every loser to get InvalidParameterException (duplicate active service name), "
        f"got {error_codes}"
    )
    # Real AWS refuses a racing loser with one of two exact duplicate-name messages, depending on
    # whether the winner's record is already registered when that loser's call lands.
    duplicate_messages = (
        "Creation of service was not idempotent.",
        "Unable to create service: a resource with the same ARN is still registered and cannot be "
        "reused yet. Retry later or use a different service name.",
    )
    for r in results:
        if isinstance(r, ClientError):
            message = r.response["Error"]["Message"]
            assert message in duplicate_messages, (
                f"expected the duplicate-name refusal message, got {message!r}"
            )

    described = ecs.describe_services(cluster=name, services=[svc_name])["services"]
    assert len(described) == 1, f"expected exactly one service record for {svc_name}, got {described}"
    assert described[0]["status"] == "ACTIVE", (
        f"expected the winning service {svc_name!r} to describe as ACTIVE, got {described[0]['status']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
