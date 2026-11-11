"""concurrent-glossary-delete-conflict-detected."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-glossary-delete-conflict-detected"
GROUP = "concurrency"
SERVICES = ["glue"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing UpdateGlossary against DeleteGlossary on one glossary: at least one commits, a loser is refused
    with AWS's exact conflict or not-found error, and the glossary ends deleted, never silently corrupted."""
    glue = ctx.client("glue")
    glossary_id = glue.create_glossary(Name=ctx.unique_name("sim2real-glossary-"))["Id"]
    ctx.on_cleanup(lambda: _safe_call(lambda: glue.delete_glossary(Identifier=glossary_id)))

    def update_call():
        return glue.update_glossary(Identifier=glossary_id, Description="updated-under-race")

    def delete_call():
        return glue.delete_glossary(Identifier=glossary_id)

    outcomes = _race([update_call, delete_call])
    update_outcome, delete_outcome = outcomes
    not_found = ("EntityNotFoundException", f'{{"Message":"Business glossary {glossary_id} not found."}}')
    conflict = ("ConcurrentModificationException", "{}")
    # The update can commit before the delete (both succeed, serialized), or lose with an
    # explicit contention signal, or with not-found when the delete fully lands first.
    assert update_outcome["error"] in (None, conflict, not_found), outcomes
    # The delete either commits, or loses to a concurrently committing update: a conflict, or
    # the in-flight update counted as a dependency of the glossary.
    dependency = (
        "ConflictException",
        f'{{"Message":"Glossary {glossary_id} cannot be deleted because of the following dependencies: '
        f'glossary {glossary_id}"}}',
    )
    assert delete_outcome["error"] in (None, conflict, dependency), outcomes
    assert update_outcome["error"] is None or delete_outcome["error"] is None, (
        f"both racers were rejected, so neither write committed: {outcomes}"
    )
    if delete_outcome["error"] is not None:
        # the update won the race: the glossary still exists and needs a real, non-raced delete
        glue.delete_glossary(Identifier=glossary_id)
    # whichever branch won, the glossary must now be gone
    get_error = _error(lambda: glue.get_glossary(Identifier=glossary_id))
    assert get_error == not_found, f"expected {not_found}, got {get_error}"
    # gone means unusable too: a mutation on the dead id must also fail, not silently no-op
    update_dead_error = _error(
        lambda: glue.update_glossary(Identifier=glossary_id, Description="post-delete-update")
    )
    assert update_dead_error == not_found, (
        f"expected {not_found} updating a deleted glossary, got {update_dead_error}"
    )

    # positive control: a normal, non-racing update-then-delete pair still works end to end
    control_id = glue.create_glossary(Name=ctx.unique_name("sim2real-glossary-ctrl-"))["Id"]
    ctx.on_cleanup(lambda: _safe_call(lambda: glue.delete_glossary(Identifier=control_id)))
    glue.update_glossary(Identifier=control_id, Description="control-update")
    glue.delete_glossary(Identifier=control_id)
    control_get_error = _error(lambda: glue.get_glossary(Identifier=control_id))
    control_not_found = ("EntityNotFoundException", f'{{"Message":"Business glossary {control_id} not found."}}')
    assert control_get_error == control_not_found, (
        f"expected {control_not_found}, got {control_get_error}"
    )


# ===== helpers =====

def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises: real AWS refuses it."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it succeeded and returned {result!r}")


def _safe_call(fn) -> None:
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _race(calls: list) -> list:
    n = len(calls)
    barrier = threading.Barrier(n)
    outcomes: list = [None] * n

    def worker(i: int, fn) -> None:
        barrier.wait()
        try:
            outcomes[i] = {"result": fn(), "error": None}
        except ClientError as e:
            outcomes[i] = {"result": None, "error": (e.response["Error"]["Code"], e.response["Error"].get("Message"))}

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(worker, i, fn) for i, fn in enumerate(calls)]
        for f in futures:
            f.result()
    return outcomes


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
