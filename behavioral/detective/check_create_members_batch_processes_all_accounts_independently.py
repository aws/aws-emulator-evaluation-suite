"""create-members-batch-processes-all-accounts-independently."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-members-batch-processes-all-accounts-independently"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """A single CreateMembers call inviting several fabricated accounts at once must
    account for every one of them (never silently drop one), and each independently
    settles at VERIFICATION_FAILED since none of the account/email pairs are real."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.

    real_account = ctx.client("sts").get_caller_identity()["Account"]
    fake_accounts = [_fake_account_id(real_account, exclude=set()) for _ in range(3)]
    for i in range(1, len(fake_accounts)):
        # guard against the tiny chance of a collision between the three fabricated ids
        assert fake_accounts[i] not in fake_accounts[:i]
    accounts = [
        {"AccountId": acc, "EmailAddress": f"sim2real-detective-{uuid.uuid4().hex[:10]}@example.com"}
        for acc in fake_accounts
    ]

    resp = d.create_members(GraphArn=arn, Accounts=accounts, DisableEmailNotification=True)
    ctx.on_cleanup(lambda: _delete_members_quietly(d, arn, fake_accounts))

    assert resp.get("UnprocessedAccounts") == [], f"unexpected UnprocessedAccounts: {resp!r}"
    processed_ids = sorted(m["AccountId"] for m in resp["Members"])
    assert processed_ids == sorted(fake_accounts), f"expected all 3 accounts processed, got {processed_ids!r}"

    def _all_statuses():
        got = d.get_members(GraphArn=arn, AccountIds=fake_accounts)
        return {m["AccountId"]: m["Status"] for m in got.get("MemberDetails", [])}

    final = _poll_until(
        probe=_all_statuses,
        predicate=lambda statuses: len(statuses) == 3 and all(s == "VERIFICATION_FAILED" for s in statuses.values()),
        timeout_s=120.0,
        interval_s=5.0,
    )
    assert set(final.keys()) == set(fake_accounts), f"expected status for all 3 accounts, got {final!r}"
    assert all(s == "VERIFICATION_FAILED" for s in final.values()), f"expected all VERIFICATION_FAILED, got {final!r}"


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


def _fake_account_id(real_account: str, exclude: set[str]) -> str:
    import random

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


def _poll_until(probe, predicate, timeout_s: float = 60.0, interval_s: float = 2.0):
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
