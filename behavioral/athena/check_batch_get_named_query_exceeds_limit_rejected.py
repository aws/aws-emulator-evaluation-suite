"""batch-get-named-query-exceeds-limit-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "batch-get-named-query-exceeds-limit-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetNamedQuery with 51 ids fails InvalidRequestException as a whole, while 50 ids including
    the same real named query id are accepted, so only the count differs between the calls."""
    athena = ctx.client("athena")
    real_id = _create_named_query(ctx, athena)
    # Ids must be well-formed (real) UUIDs -- a batch of ids that are the right shape but not
    # valid UUID version/variant nibbles is rejected up front with a distinct "at least one
    # valid named query Id is required" InvalidRequestException, which would be
    # indistinguishable from the over-limit rejection this check targets.
    bogus_ids = [str(uuid.uuid4()) for _ in range(50)]

    too_many = [real_id] + bogus_ids
    code, message = _error(lambda: athena.batch_get_named_query(NamedQueryIds=too_many))
    assert code == "InvalidRequestException", (
        f"expected InvalidRequestException for 51 ids (1 real + 50 bogus), got {code}"
    )
    assert message == (
        "1 validation error detected: Value at 'namedQueryIds' failed to satisfy constraint: "
        "Member must have length less than or equal to 50"
    ), repr(message)

    # Drop to exactly 50 ids using the SAME real id + 49 of the SAME bogus ids: the request is
    # now accepted, the real one comes back resolved, and the other 49 are unprocessed.
    exactly_fifty = [real_id] + bogus_ids[:49]
    resp = athena.batch_get_named_query(NamedQueryIds=exactly_fifty)
    resolved_ids = [q["NamedQueryId"] for q in resp["NamedQueries"]]
    assert resolved_ids == [real_id], f"expected only {real_id} resolved, got {resolved_ids}"
    # UnprocessedNamedQueryIds is a list of {NamedQueryId, ErrorCode, ErrorMessage} objects,
    # not bare id strings -- pull out the ids before comparing.
    unprocessed_ids = {u["NamedQueryId"] for u in resp["UnprocessedNamedQueryIds"]}
    assert unprocessed_ids == set(bogus_ids[:49]), (
        f"expected 49 unprocessed bogus ids, got {resp['UnprocessedNamedQueryIds']}"
    )


def _error(fn):
    """Call fn() and return its ClientError (code, message); a call that succeeds fails the check."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_named_query(ctx, athena):
    name = ctx.unique_name("sim2real-behav-nq-")
    resp = athena.create_named_query(Name=name, Database="default", QueryString="SELECT 1")
    named_query_id = resp["NamedQueryId"]
    ctx.on_cleanup(lambda: athena.delete_named_query(NamedQueryId=named_query_id))
    return named_query_id


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
