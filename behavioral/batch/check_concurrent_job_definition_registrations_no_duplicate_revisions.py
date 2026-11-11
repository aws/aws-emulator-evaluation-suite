"""concurrent-job-definition-registrations-no-duplicate-revisions."""

from __future__ import annotations
from collections.abc import Callable

from behavioral_harness import tags


CHECK = "concurrent-job-definition-registrations-no-duplicate-revisions"
GROUP = 'concurrency'
SERVICES = ['batch']

_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"}


def _swallow(fn):
    """Run fn(), swallowing any exception (best-effort teardown step)."""
    fn()


def _deregister_jd(bat, name, revision):
    _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{revision}"))


def _parallel(fns: list[Callable]) -> tuple[list, list[str]]:
    """Run callables concurrently; return (successful results, error codes)."""
    import concurrent.futures

    oks: list = []
    errs: list[str] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(fn) for fn in fns]
        for fut in futures:
            try:
                oks.append(fut.result())
            except Exception as exc:  # noqa: BLE001
                resp = getattr(exc, "response", None) or {}
                errs.append(resp.get("Error", {}).get("Code", type(exc).__name__))
    return oks, errs


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """N concurrent RegisterJobDefinition calls for the same name yield N distinct revisions."""
    bat = ctx.client("batch")
    name = ctx.unique_name("sim2real-behav-jd-race-")
    n = 8

    def register(i: int):
        return bat.register_job_definition(
            jobDefinitionName=name,
            type="container",
            containerProperties={"image": "busybox:1.36", "vcpus": 1, "memory": 128, "command": ["echo", str(i)]},
            tags=_MANAGED_TAGS,
        )

    oks, errs = _parallel([lambda i=i: register(i) for i in range(n)])
    assert oks, f"expected at least one concurrent registration to succeed, errors: {errs}"

    revisions = sorted(r["revision"] for r in oks)
    for rev in revisions:
        ctx.on_cleanup(lambda r=rev: _deregister_jd(bat, name, r))

    # Real AWS serializes revision assignment: losers of the race are rejected
    # with ClientException rather than being handed a duplicate revision.
    assert all(e == "ClientException" for e in errs), (
        f"concurrent registration losers must fail with ClientException, got {errs}"
    )
    assert len(set(revisions)) == len(revisions), (
        f"revision assignment must be serialized under contention: concurrent "
        f"registrations produced duplicate revisions {revisions}"
    )
    arns = {r["jobDefinitionArn"] for r in oks}
    assert len(arns) == len(oks), (
        f"each revision must get a distinct ARN, got {len(arns)} for {len(oks)} registrations"
    )

    active = bat.describe_job_definitions(jobDefinitionName=name, status="ACTIVE")["jobDefinitions"]
    persisted = sorted(d["revision"] for d in active)
    assert persisted == revisions, (
        f"every acknowledged revision must be durably readable afterwards: "
        f"acked {revisions} but describe returned {persisted}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
