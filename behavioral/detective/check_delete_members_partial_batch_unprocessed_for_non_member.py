"""delete-members-partial-batch-unprocessed-for-non-member."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags

CHECK = "delete-members-partial-batch-unprocessed-for-non-member"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """DeleteMembers given a mix of a real member and an account that was never invited
    must partition the two: the real member is removed and echoed in AccountIds, and the
    non-member is reported in UnprocessedAccounts -- never silently merged or dropped."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.

    real_account = ctx.client("sts").get_caller_identity()["Account"]
    real_member_account = _fake_account_id(real_account, exclude=set())
    never_invited_account = _fake_account_id(real_account, exclude={real_member_account})
    email = f"sim2real-detective-{uuid.uuid4().hex[:10]}@example.com"

    create_resp = d.create_members(
        GraphArn=arn,
        Accounts=[{"AccountId": real_member_account, "EmailAddress": email}],
        DisableEmailNotification=True,
    )
    assert create_resp["Members"][0]["AccountId"] == real_member_account, (
        f"expected CreateMembers to echo {real_member_account!r}, got {create_resp!r}"
    )

    delete_resp = d.delete_members(GraphArn=arn, AccountIds=[real_member_account, never_invited_account])

    assert delete_resp["AccountIds"] == [real_member_account], (
        f"expected only the real member echoed as processed, got {delete_resp!r}"
    )
    unprocessed_ids = [u["AccountId"] for u in delete_resp.get("UnprocessedAccounts", [])]
    assert unprocessed_ids == [never_invited_account], (
        f"expected the never-invited account as unprocessed, got {delete_resp!r}"
    )

    final = _poll_until(
        probe=lambda: d.get_members(GraphArn=arn, AccountIds=[real_member_account])["MemberDetails"],
        predicate=lambda members: members == [],
        timeout_s=60.0,
        interval_s=3.0,
    )
    assert final == [], f"expected the real member gone after DeleteMembers, got {final!r}"


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
