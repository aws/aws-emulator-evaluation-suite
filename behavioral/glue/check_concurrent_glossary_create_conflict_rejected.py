"""concurrent-glossary-create-conflict-rejected."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-glossary-create-conflict-rejected"
GROUP = "concurrency"
SERVICES = ["glue"]


def _error(fn):
    """Call fn(); return its (code, message). An unexpected success raises: real AWS refuses it."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it succeeded and returned {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Two simultaneous CreateGlossary calls with one new Name: exactly one succeeds and the other gets the
    same AlreadyExistsException a sequential duplicate gets; GetGlossary reflects only the winner."""
    glue = ctx.client("glue")
    name = ctx.unique_name("sim2real-glossary-createrace-")

    def _create(desc):
        return glue.create_glossary(Name=name, Description=desc)

    results = _race([lambda: _create("racer-a"), lambda: _create("racer-b")])
    successes = [r for r, c in results if c is None]
    failures = [c for _, c in results if c is not None]
    already_exists = ("AlreadyExistsException", f'{{"Message":"A glossary with name \'{name}\' already exists."}}')

    assert len(successes) == 1, f"expected exactly one success, got results={results}"
    winner_id = successes[0]["Id"]
    winner_desc = successes[0]["Description"]
    ctx.on_cleanup(lambda: _safe(lambda: glue.delete_glossary(Identifier=winner_id)))
    # Empirically, the loser of a CreateGlossary name race gets AlreadyExistsException, not
    # ConcurrentModificationException: the name-uniqueness check behaves like a conditional
    # create rather than a lock conflict.
    assert failures == [already_exists], (
        f"expected exactly one AlreadyExistsException, got {results}"
    )

    # Boundary control: once the name is committed, a further sequential (non-racing) create
    # gets the identical AlreadyExistsException.
    sequential = _error(lambda: glue.create_glossary(Name=name, Description="racer-c-sequential"))
    assert sequential == already_exists, sequential

    # Terminal, independent read at the destination: GetGlossary reflects only the winning
    # write; the losing racer (and the sequential control above) created nothing.
    got = glue.get_glossary(Identifier=winner_id)
    assert got["Name"] == name and got["Description"] == winner_desc, got


# ===== helpers =====
def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise


def _race(fns):
    with ThreadPoolExecutor(max_workers=len(fns)) as pool:
        futures = [pool.submit(fn) for fn in fns]
        results = []
        for fut in futures:
            try:
                results.append((fut.result(), None))
            except ClientError as exc:
                err = exc.response.get("Error", {})
                results.append((None, (err.get("Code"), err.get("Message"))))
    return results


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
