"""concurrent-glossary-term-create-conflict-rejected."""
from __future__ import annotations

import sys
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-glossary-term-create-conflict-rejected"
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
    """Two simultaneous CreateGlossaryTerm calls with one new Name in one glossary: exactly one succeeds and
    the other gets the same AlreadyExistsException a sequential duplicate gets; GetGlossaryTerm
    reflects only the winner."""
    glue = ctx.client("glue")

    glossary_id = glue.create_glossary(Name=ctx.unique_name("sim2real-glossary-"))["Id"]
    term_name = ctx.unique_name("sim2real-term-createrace-")

    def _create(short_desc):
        return glue.create_glossary_term(
            GlossaryIdentifier=glossary_id, Name=term_name, ShortDescription=short_desc
        )

    results = _race([lambda: _create("racer-a"), lambda: _create("racer-b")])
    successes = [r for r, c in results if c is None]
    failures = [c for _, c in results if c is not None]
    already_exists = (
        "AlreadyExistsException",
        f'{{"Message":"A glossary term with name \'{term_name}\' already exists in glossary \'{glossary_id}\'."}}',
    )

    try:
        assert len(successes) == 1, f"expected exactly one success, got results={results}"
        winner_id = successes[0]["Id"]
        winner_desc = successes[0]["ShortDescription"]
        ctx.on_cleanup(lambda: _safe(lambda: glue.delete_glossary_term(Identifier=winner_id)))
        # Empirically, the loser of a CreateGlossaryTerm name race gets AlreadyExistsException,
        # not ConcurrentModificationException: the term-name-uniqueness check behaves like a
        # conditional create rather than a lock conflict.
        assert failures == [already_exists], (
            f"expected exactly one AlreadyExistsException, got {results}"
        )

        # Effect: GetGlossaryTerm reflects only the winning write.
        got = glue.get_glossary_term(Identifier=winner_id)
        assert got["Name"] == term_name and got["ShortDescription"] == winner_desc, (
            f"expected Name={term_name!r} ShortDescription={winner_desc!r}, got {got}"
        )

        # Boundary control: once the name is committed under this glossary, a further
        # sequential (non-racing) create gets the identical AlreadyExistsException.
        sequential = _error(
            lambda: glue.create_glossary_term(
                GlossaryIdentifier=glossary_id, Name=term_name, ShortDescription="racer-c-sequential"
            )
        )
        assert sequential == already_exists, f"expected {already_exists}, got {sequential}"
    finally:
        # DeleteGlossary requires all terms to be removed first.
        for r, c in results:
            if c is None:
                _safe(lambda term_id=r["Id"]: glue.delete_glossary_term(Identifier=term_id))
        _safe(lambda: glue.delete_glossary(Identifier=glossary_id))


# ===== helpers =====
def _safe(fn):
    """Run a delete; EntityNotFoundException is done. A failure names the error in flight, so a
    body failure is never hidden behind it."""
    found = sys.exc_info()[1]
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "EntityNotFoundException":
            raise RuntimeError(
                (f"{found!r}; " if found else "") + f"teardown delete failed: {exc!r}"
            ) from exc


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
