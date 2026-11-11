"""pending-aggregation-request-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "pending-aggregation-request-lifecycle"
GROUP = "state-machine"
SERVICES = ["config"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "identity:standalone", "phase:standalone", "plane:control")
def run(ctx) -> None:
    """DeletePendingAggregationRequest for a requester with no pending request succeeds as a
    no-op, and DescribePendingAggregationRequests returns the same list before, after, and on an
    immediate re-read.
    """
    config = ctx.client("config")
    fake_account_id = "111122223333"
    region = ctx.region

    before = config.describe_pending_aggregation_requests()["PendingAggregationRequests"]
    assert not _has_request(before, fake_account_id, region), (
        f"fixture account {fake_account_id}/{region} must not already appear in "
        f"PendingAggregationRequests: {before!r}"
    )

    # a well-formed delete for a request that does not exist is an idempotent no-op (no
    # NotFound-style error is modeled for this operation)
    config.delete_pending_aggregation_request(
        RequesterAccountId=fake_account_id, RequesterAwsRegion=region
    )

    after = config.describe_pending_aggregation_requests()["PendingAggregationRequests"]
    assert not _has_request(after, fake_account_id, region), (
        f"delete on an absent request must not conjure one into existence: {after!r}"
    )
    assert after == before, f"delete on an absent request must not perturb the list: {before!r} -> {after!r}"

    # freeze detector: an immediate re-read must return the identical list again -- a target
    # that mutates state on a read, or whose listing is non-deterministically ordered, fails
    # this even though nothing else touched the account between the two calls.
    again = config.describe_pending_aggregation_requests()["PendingAggregationRequests"]
    assert again == after, f"a bare re-read must not change the list: {after!r} -> {again!r}"


def _has_request(requests, account_id: str, region: str) -> bool:
    return any(
        r.get("RequesterAccountId") == account_id and r.get("RequesterAwsRegion") == region
        for r in requests
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
