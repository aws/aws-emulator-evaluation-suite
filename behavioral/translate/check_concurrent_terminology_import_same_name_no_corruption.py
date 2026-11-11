"""concurrent-terminology-import-same-name-no-corruption."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-terminology-import-same-name-no-corruption"
GROUP = "concurrency"
SERVICES = ["translate"]

def _csv_with_n_terms(n: int) -> bytes:
    rows = "".join(f"Term{i},Term{i}Es\n" for i in range(n))
    return f"en,es\n{rows}".encode()


# Each racer submits DIFFERENT content (distinct term counts), not the same bytes five times.
# Identical-content races can't distinguish "properly serialized" from "silently corrupted" --
# the final TermCount would be 3 either way. With distinct counts, a mixed/partial write produces
# a TermCount that matches none of the individual submissions, which is what "no corruption" means.
_RACER_TERM_COUNTS = [1, 2, 3, 4, 5]


def _import_once(translate, name: str, body: bytes):
    try:
        resp = translate.import_terminology(
            Name=name,
            MergeStrategy="OVERWRITE",
            TerminologyData={"File": body, "Format": "CSV"},
        )
        return ("ok", resp["TerminologyProperties"]["TermCount"])
    except ClientError as e:
        return ("error", e.response["Error"]["Code"])


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent ImportTerminology calls on one Name with different term counts each succeed with
    their own term count or fail with a ClientError, at least one succeeds, and the final TermCount
    equals a successful call's count, never a mixed write."""
    translate = ctx.client("translate")
    name = ctx.unique_name("sim2real-term-race-")
    ctx.on_cleanup(lambda: translate.delete_terminology(Name=name))

    bodies = [_csv_with_n_terms(n) for n in _RACER_TERM_COUNTS]
    with ThreadPoolExecutor(max_workers=len(bodies)) as pool:
        futures = {
            pool.submit(_import_once, translate, name, body): expected
            for body, expected in zip(bodies, _RACER_TERM_COUNTS)
        }
        results = [(futures[f], *f.result()) for f in as_completed(futures)]

    ok_term_counts = set()
    for expected, outcome, detail in results:
        if outcome == "ok":
            assert detail == expected, (expected, detail)
            ok_term_counts.add(detail)
        else:
            # Any contention error is acceptable here (exact code is not contractually
            # guaranteed under a race); what matters is no corruption of final state.
            assert isinstance(detail, str) and detail, detail

    assert ok_term_counts, results

    final = translate.get_terminology(Name=name)["TerminologyProperties"]
    assert final["TermCount"] in ok_term_counts, (final["TermCount"], ok_term_counts)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
