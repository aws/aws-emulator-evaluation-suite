"""create-members-verification-fails-for-nonexistent-account."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-members-verification-fails-for-nonexistent-account"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "cap:c4", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """CreateMembers with a fabricated 12-digit account id and email records one member that ends
    VERIFICATION_FAILED, because the account id and email do not match a real account."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # An account administers at most one behavior graph per Region; CreateGraph returns that
    # graph, so it is left in place.

    fake_account = _fake_account_id(ctx)
    email = f"sim2real-detective-{uuid.uuid4().hex[:10]}@example.com"

    resp = d.create_members(
        GraphArn=arn,
        Accounts=[{"AccountId": fake_account, "EmailAddress": email}],
        DisableEmailNotification=True,
    )
    ctx.on_cleanup(lambda: _delete_members_quietly(d, arn, [fake_account]))

    assert resp["UnprocessedAccounts"] == [], f"unexpected unprocessed: {resp}"
    members = resp["Members"]
    assert len(members) == 1 and members[0]["AccountId"] == fake_account, (
        f"expected exactly one member echoed back for {fake_account!r}, got {members!r}"
    )

    final = _poll_until(
        probe=lambda: _get_member_status(d, arn, fake_account),
        predicate=lambda status: status in ("INVITED", "VERIFICATION_FAILED"),
        timeout_s=90.0,
        interval_s=3.0,
    )
    assert final == "VERIFICATION_FAILED", f"expected VERIFICATION_FAILED, got {final!r}"


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


def _fake_account_id(ctx) -> str:
    import random

    real_account = ctx.client("sts").get_caller_identity()["Account"]
    while True:
        candidate = "9" + "".join(str(random.randint(0, 9)) for _ in range(11))
        if candidate != real_account:
            return candidate


def _get_member_status(d, graph_arn: str, account_id: str) -> str:
    resp = d.get_members(GraphArn=graph_arn, AccountIds=[account_id])
    details = resp.get("MemberDetails", [])
    assert len(details) == 1, f"expected exactly one member detail, got {details!r}"
    return details[0]["Status"]


def _delete_members_quietly(d, graph_arn: str, account_ids: list[str]) -> None:
    from botocore.exceptions import ClientError

    try:
        d.delete_members(GraphArn=graph_arn, AccountIds=account_ids)
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
