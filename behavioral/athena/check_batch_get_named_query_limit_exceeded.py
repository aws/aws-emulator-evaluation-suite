"""batch-get-named-query-limit-exceeded."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "batch-get-named-query-limit-exceeded"
GROUP = 'overly-permissive'
SERVICES = ['athena']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetNamedQuery rejects more than 50 NamedQueryIds outright with no partial result, while
    50 ids including a real one are accepted and processed."""
    athena = ctx.client("athena")

    # Well-formed (real) UUIDs -- ids that are the right shape but not valid UUID
    # version/variant nibbles are rejected up front with a distinct "at least one valid
    # named query Id is required" InvalidRequestException, which would be indistinguishable
    # from the over-limit rejection this check targets.
    too_many = [str(uuid.uuid4()) for _ in range(51)]
    code, message = _error(lambda: athena.batch_get_named_query(NamedQueryIds=too_many))
    assert code == "InvalidRequestException", f"expected InvalidRequestException for 51 ids, got {code}"
    assert message == (
        "1 validation error detected: Value at 'namedQueryIds' failed to satisfy constraint: "
        "Member must have length less than or equal to 50"
    ), repr(message)

    # Positive control: the same shape of call one under the limit is accepted. A batch of
    # 50 *entirely* bogus ids is itself rejected with the "at least one valid named query Id
    # is required" InvalidRequestException, so mix in one real, existing named query id to
    # prove the limit -- not blanket rejection -- is what tripped above.
    name = ctx.unique_name("sim2real-behav-nq-")
    real_id = athena.create_named_query(Name=name, Database="default", QueryString="SELECT 1")["NamedQueryId"]
    ctx.on_cleanup(lambda: athena.delete_named_query(NamedQueryId=real_id))

    bogus_ids = [str(uuid.uuid4()) for _ in range(49)]
    resp = athena.batch_get_named_query(NamedQueryIds=[real_id] + bogus_ids)
    resolved_ids = [nq["NamedQueryId"] for nq in resp["NamedQueries"]]
    assert resolved_ids == [real_id], f"expected only the real id to resolve, got {resolved_ids}"
    unprocessed_ids = {u["NamedQueryId"] for u in resp["UnprocessedNamedQueryIds"]}
    assert unprocessed_ids == set(bogus_ids), f"expected the 49 bogus ids unprocessed, got {resp['UnprocessedNamedQueryIds']}"


def _error(fn):
    """Call fn() and return its ClientError (code, message); a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError("expected BatchGetNamedQuery with 51 ids to raise, it succeeded")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
