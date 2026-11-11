"""concurrent-named-query-delete-race-single-success."""
from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-named-query-delete-race-single-success"
GROUP = "concurrency"
SERVICES = ["athena"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two racing DeleteNamedQuery calls on one id each succeed or fail InvalidRequestException naming
    the id, at least one succeeds, and a later GetNamedQuery and DeleteNamedQuery fail the same way."""
    athena = ctx.client("athena")
    nq = athena.create_named_query(
        Name=ctx.unique_name("sim2real-athena-nq-"),
        Database="default",
        QueryString="SELECT 1",
    )
    query_id = nq["NamedQueryId"]
    ctx.on_cleanup(lambda: _safe_delete(athena, query_id))

    expected_missing = f"NamedQuery: {query_id} does not exist"
    barrier = threading.Barrier(2)

    def _delete():
        barrier.wait(timeout=30)
        try:
            athena.delete_named_query(NamedQueryId=query_id)
            return ("ok", None, None)
        except ClientError as exc:
            return ("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        outcomes = [f.result() for f in [pool.submit(_delete) for _ in range(2)]]

    successes = [o for o in outcomes if o[0] == "ok"]
    assert successes, f"expected at least one of the racing deletes to succeed, got {outcomes}"
    for outcome in outcomes:
        assert outcome[0] == "ok" or outcome[1:] == ("InvalidRequestException", expected_missing), (
            f"a racing delete may only succeed or be refused with InvalidRequestException "
            f"{expected_missing!r}, got {outcome}"
        )

    # Effect: the named query is actually gone (GetNamedQuery on a deleted id
    # is rejected -- the delete had a real, durable effect, it wasn't a no-op
    # success masking a lost update).
    code, message = _error(lambda: athena.get_named_query(NamedQueryId=query_id))
    assert code == "InvalidRequestException", (
        f"expected GetNamedQuery on the deleted id to be rejected with "
        f"InvalidRequestException, got {code!r}"
    )
    assert message == expected_missing, repr(message)

    # A further delete of the now-gone id is refused with the same error, so the racing
    # successes reflected one real delete, not a permanently idempotent no-op.
    code, message = _error(lambda: athena.delete_named_query(NamedQueryId=query_id))
    assert code == "InvalidRequestException", (
        f"expected a third DeleteNamedQuery on the now-gone id to be rejected "
        f"with InvalidRequestException, got {code!r}"
    )
    assert message == expected_missing, repr(message)


def _safe_delete(athena, query_id: str) -> None:
    try:
        athena.delete_named_query(NamedQueryId=query_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "InvalidRequestException":
            raise


def _error(fn):
    """Call fn() and return its ClientError (code, message); a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
