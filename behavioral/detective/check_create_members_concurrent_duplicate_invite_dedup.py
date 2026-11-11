"""create-members-concurrent-duplicate-invite-dedup."""
from __future__ import annotations

import time
import uuid
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-members-concurrent-duplicate-invite-dedup"
GROUP = "concurrency"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """Firing several concurrent CreateMembers calls that all invite the exact same account
    to the same graph must not create duplicate member records: after all calls settle,
    GetMembers must show exactly one MemberDetails entry for that account."""
    d = ctx.client("detective")
    arn = d.create_graph()["GraphArn"]
    ctx.on_cleanup(lambda: _delete_graph_quietly(d, arn))

    fake_account = _fake_account_id(ctx)
    email = f"sim2real-detective-{uuid.uuid4().hex[:10]}@example.com"
    ctx.on_cleanup(lambda: _delete_members_quietly(d, arn, [fake_account]))

    def _invite():
        return d.create_members(
            GraphArn=arn,
            Accounts=[{"AccountId": fake_account, "EmailAddress": email}],
            DisableEmailNotification=True,
        )

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(lambda _: _invite(), range(5)))

    # Every concurrent call must complete without raising (already guaranteed by map above)
    # and must account for the single target account either as a processed member or as an
    # already-being-processed unprocessed entry -- never silently drop it.
    for resp in results:
        seen = {m["AccountId"] for m in resp.get("Members", [])} | {
            u["AccountId"] for u in resp.get("UnprocessedAccounts", [])
        }
        assert fake_account in seen, f"call dropped the target account entirely: {resp!r}"

    final_members = _poll_until(
        probe=lambda: d.get_members(GraphArn=arn, AccountIds=[fake_account])["MemberDetails"],
        predicate=lambda members: len(members) >= 1,
        timeout_s=30.0,
        interval_s=2.0,
    )
    assert len(final_members) == 1, f"expected exactly one member record, got {final_members!r}"
    assert final_members[0]["AccountId"] == fake_account, (
        f"expected the sole member record to name {fake_account}, got {final_members[0]!r}"
    )


def _fake_account_id(ctx) -> str:
    import random

    real_account = ctx.client("sts").get_caller_identity()["Account"]
    while True:
        candidate = "9" + "".join(str(random.randint(0, 9)) for _ in range(11))
        if candidate != real_account:
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
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
