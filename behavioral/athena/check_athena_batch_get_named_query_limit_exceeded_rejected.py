"""athena-batch-get-named-query-limit-exceeded-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "athena-batch-get-named-query-limit-exceeded-rejected"
GROUP = "overly-permissive"
SERVICES = ["athena"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """BatchGetNamedQuery with more than 50 ids is rejected outright (no partial processing).

    At exactly 50 ids the real id resolves and the bogus ids are returned as unprocessed.
    """
    athena = ctx.client("athena")

    query_name = ctx.unique_name("sim2real-athena-nq-")
    real_id = athena.create_named_query(
        Name=query_name,
        Database="default",
        QueryString="SELECT 1",
    )["NamedQueryId"]
    ctx.on_cleanup(lambda: athena.delete_named_query(NamedQueryId=real_id))

    bogus_ids = [f"00000000-0000-0000-0000-{i:012d}" for i in range(50)]

    from botocore.exceptions import ClientError

    # Including a real id keeps Athena's separate "at least one valid named query Id" rule
    # from explaining the rejection; only the 51-id count can.
    try:
        athena.batch_get_named_query(NamedQueryIds=[real_id] + bogus_ids)
        raise AssertionError(
            "expected BatchGetNamedQuery with 51 ids (1 real + 50 bogus) to raise "
            "InvalidRequestException"
        )
    except ClientError as exc:
        code, message = exc.response["Error"]["Code"], exc.response["Error"].get("Message")
        assert code == "InvalidRequestException", f"expected InvalidRequestException, got {code}"
        assert message == (
            "1 validation error detected: Value at 'namedQueryIds' failed to satisfy constraint: "
            "Member must have length less than or equal to 50"
        ), repr(message)

    # Same ids minus one bogus id: only the count differs from the rejected call.
    resp = athena.batch_get_named_query(NamedQueryIds=[real_id] + bogus_ids[:49])
    resolved_ids = [nq["NamedQueryId"] for nq in resp["NamedQueries"]]
    assert resolved_ids == [real_id], f"expected only {real_id} resolved, got {resolved_ids}"
    unprocessed_count = len(resp["UnprocessedNamedQueryIds"])
    assert unprocessed_count == 49, f"expected 49 unprocessed ids, got {unprocessed_count}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
