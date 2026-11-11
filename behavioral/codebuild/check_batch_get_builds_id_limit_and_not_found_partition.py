"""batch-get-builds-id-limit-and-not-found-partition."""
from __future__ import annotations

import uuid

from botocore.exceptions import ClientError
from behavioral_harness import tags

# ===== helpers =====


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raised. An unexpected
    SUCCESS raises, so an over-permissive target is never read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


# ===== check =====

CHECK = "batch-get-builds-id-limit-and-not-found-partition"
GROUP = 'error-semantics'
SERVICES = ['codebuild']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetBuilds accepts exactly 100 ids and partitions ALL of them into buildsNotFound,
    and rejects 101 ids with InvalidInputException."""
    cb = ctx.client("codebuild")
    absent_project = ctx.unique_name("sim2real-behav-absent-proj-")
    ids = [f"{absent_project}:{uuid.uuid4()}" for _ in range(101)]

    # --- control / at-the-limit: exactly 100 ids is accepted, and all 100 are reported.
    at_limit = ids[:100]
    resp = cb.batch_get_builds(ids=at_limit)
    assert resp.get("builds", []) == [], resp.get("builds")
    not_found = resp.get("buildsNotFound", [])
    assert len(not_found) == 100, (
        f"buildsNotFound must report every absent id: got {len(not_found)} of 100"
    )
    assert set(not_found) == set(at_limit), (
        "buildsNotFound must be exactly the requested set; "
        f"missing={sorted(set(at_limit) - set(not_found))[:3]} "
        f"extra={sorted(set(not_found) - set(at_limit))[:3]}"
    )

    # --- negative: one id over the modelled maximum is refused.
    code, message = _error(lambda: cb.batch_get_builds(ids=ids))
    assert (code, message) == (
        "InvalidInputException",
        "The maximum length of input resource list is 100 but input list with size 101 is found.",
    ), (code, message)

    # Effect absent / control still works: the 100-id call is still served afterwards.
    again = cb.batch_get_builds(ids=at_limit)
    assert len(again.get("buildsNotFound", [])) == 100, again


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
