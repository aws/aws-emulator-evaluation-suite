"""delete-members-removes-member-record."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "delete-members-removes-member-record"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """After DeleteMembers, the member record for the account ceases to exist: GetMembers
    must no longer return it in MemberDetails and must instead report it as an
    UnprocessedAccount."""
    d = ctx.client("detective")
    arn = d.create_graph()["GraphArn"]
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.

    fake_account = _fake_account_id(ctx)
    email = f"sim2real-detective-{uuid.uuid4().hex[:10]}@example.com"

    create_resp = d.create_members(
        GraphArn=arn,
        Accounts=[{"AccountId": fake_account, "EmailAddress": email}],
        DisableEmailNotification=True,
    )
    assert create_resp["Members"][0]["AccountId"] == fake_account

    delete_resp = d.delete_members(GraphArn=arn, AccountIds=[fake_account])
    assert delete_resp.get("UnprocessedAccounts") == [], f"unexpected: {delete_resp}"
    assert delete_resp["AccountIds"] == [fake_account]

    final = _poll_until(
        probe=lambda: d.get_members(GraphArn=arn, AccountIds=[fake_account]),
        predicate=lambda resp: resp.get("MemberDetails", []) == [],
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert final["MemberDetails"] == []
    unprocessed = {u["AccountId"]: u.get("Reason") for u in final.get("UnprocessedAccounts", [])}
    assert fake_account in unprocessed, f"expected {fake_account} in {unprocessed!r}"
    assert unprocessed[fake_account] == "No such membership", (
        f"expected the specific no-longer-a-member reason, got {unprocessed[fake_account]!r}"
    )


def _fake_account_id(ctx) -> str:
    import random

    real_account = ctx.client("sts").get_caller_identity()["Account"]
    while True:
        candidate = "9" + "".join(str(random.randint(0, 9)) for _ in range(11))
        if candidate != real_account:
            return candidate


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
