"""get-members-partitions-processed-and-unprocessed."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-members-partitions-processed-and-unprocessed"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """A single GetMembers call for a mix of a real member and an account that was never
    added must partition them correctly: the real member lands in MemberDetails and the
    unknown account lands in UnprocessedAccounts -- never both, never neither."""
    d = ctx.client("detective")
    arn = d.create_graph()["GraphArn"]
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.

    known_account = _fake_account_id(ctx, exclude=set())
    unknown_account = _fake_account_id(ctx, exclude={known_account})
    email = f"sim2real-detective-{uuid.uuid4().hex[:10]}@example.com"

    d.create_members(
        GraphArn=arn,
        Accounts=[{"AccountId": known_account, "EmailAddress": email}],
        DisableEmailNotification=True,
    )
    ctx.on_cleanup(lambda: _delete_members_quietly(d, arn, [known_account]))

    resp = _poll_until(
        probe=lambda: d.get_members(GraphArn=arn, AccountIds=[known_account, unknown_account]),
        predicate=lambda r: len(r.get("MemberDetails", [])) + len(r.get("UnprocessedAccounts", [])) == 2,
        timeout_s=30.0,
        interval_s=2.0,
    )

    member_ids = [m["AccountId"] for m in resp["MemberDetails"]]
    unprocessed_ids = [u["AccountId"] for u in resp["UnprocessedAccounts"]]

    assert member_ids == [known_account], f"unexpected MemberDetails ids: {member_ids!r}"
    assert unprocessed_ids == [unknown_account], f"unexpected UnprocessedAccounts ids: {unprocessed_ids!r}"


def _fake_account_id(ctx, exclude: set[str]) -> str:
    import random

    real_account = ctx.client("sts").get_caller_identity()["Account"]
    while True:
        candidate = "9" + "".join(str(random.randint(0, 9)) for _ in range(11))
        if candidate != real_account and candidate not in exclude:
            return candidate


def _delete_members_quietly(d, graph_arn: str, account_ids: list[str]) -> None:
    from botocore.exceptions import ClientError

    try:
        d.delete_members(GraphArn=graph_arn, AccountIds=account_ids)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _delete_graph_quietly(d, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        d.delete_graph(GraphArn=arn)
    except ClientError:
        pass


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s; last={last!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
