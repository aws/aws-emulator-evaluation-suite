"""batch-get-graph-member-datasources-unprocessed-for-non-member."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "batch-get-graph-member-datasources-unprocessed-for-non-member"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """BatchGetGraphMemberDatasources returns the graph administrator's own account in MemberDatasources and a
    non-member account only in UnprocessedAccounts, so the split is not "every account unprocessed"."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # An account administers at most one behavior graph per Region; CreateGraph returns that
    # graph, so it is left in place.

    own_account_id = ctx.client("sts").get_caller_identity()["Account"]
    non_member_account_id = _fake_account_id(ctx, exclude={own_account_id})

    resp = _poll_until(
        probe=lambda: d.batch_get_graph_member_datasources(
            GraphArn=arn, AccountIds=[own_account_id, non_member_account_id]
        ),
        predicate=lambda r: own_account_id in [m["AccountId"] for m in r.get("MemberDatasources", [])],
        timeout_s=30.0,
        interval_s=2.0,
    )

    datasource_ids = [m["AccountId"] for m in resp["MemberDatasources"]]
    unprocessed_ids = [u["AccountId"] for u in resp["UnprocessedAccounts"]]
    assert own_account_id in datasource_ids, (
        f"expected the administrator's own account in MemberDatasources, got {resp!r}"
    )
    assert non_member_account_id in unprocessed_ids, (
        f"expected the non-member account in UnprocessedAccounts, got {resp!r}"
    )
    assert non_member_account_id not in datasource_ids, (
        f"fabricated MemberDatasources for a non-member account: {resp!r}"
    )
    assert own_account_id not in unprocessed_ids, (
        f"administrator account incorrectly reported unprocessed: {resp!r}"
    )


def _create_graph_with_retry(d, retries: int = 8, base_delay: float = 5.0) -> str:
    from botocore.exceptions import ClientError

    for attempt in range(retries):
        try:
            return d.create_graph()["GraphArn"]
        except ClientError as e:
            code = e.response["Error"]["Code"]
            if code in ("TooManyRequestsException", "ThrottlingException") and attempt < retries - 1:
                time.sleep(base_delay * (attempt + 1))
                continue
            raise
    raise AssertionError("create_graph did not succeed after retries")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


def _fake_account_id(ctx, exclude: set[str]) -> str:
    import random

    real_account = ctx.client("sts").get_caller_identity()["Account"]
    while True:
        candidate = "9" + "".join(str(random.randint(0, 9)) for _ in range(11))
        if candidate != real_account and candidate not in exclude:
            return candidate


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
