"""get-members-unprocessed-for-never-invited-account."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-members-unprocessed-for-never-invited-account"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """GetMembers for an account that was never invited returns it in UnprocessedAccounts, not
    as an error -- and does so because it was never invited, not because this GetMembers call
    can never populate MemberDetails at all."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.

    # Positive control: an account this graph actually invited must appear in MemberDetails,
    # so a target that dumps every account into UnprocessedAccounts cannot pass this check.
    invited_account_id = _fake_account_id(ctx)
    invited_email = f"sim2real-detective-{uuid.uuid4().hex[:10]}@example.com"
    d.create_members(
        GraphArn=arn,
        Accounts=[{"AccountId": invited_account_id, "EmailAddress": invited_email}],
        DisableEmailNotification=True,
    )
    ctx.on_cleanup(lambda: _delete_members_quietly(d, arn, [invited_account_id]))

    control_resp = _poll_until(
        probe=lambda: d.get_members(GraphArn=arn, AccountIds=[invited_account_id]),
        predicate=lambda r: len(r.get("MemberDetails", [])) + len(r.get("UnprocessedAccounts", [])) == 1,
        timeout_s=30.0,
        interval_s=2.0,
    )
    control_member_ids = [m["AccountId"] for m in control_resp.get("MemberDetails", [])]
    assert control_member_ids == [invited_account_id], (
        f"positive control failed: expected {invited_account_id!r} in MemberDetails, got {control_resp!r}"
    )

    never_invited_account_id = _fake_account_id(ctx, exclude={invited_account_id})

    resp = d.get_members(GraphArn=arn, AccountIds=[never_invited_account_id])
    assert resp.get("MemberDetails", []) == [], f"expected no MemberDetails, got {resp!r}"
    unprocessed = resp.get("UnprocessedAccounts", [])
    unprocessed_ids = [u["AccountId"] for u in unprocessed]
    assert never_invited_account_id in unprocessed_ids, (
        f"expected the never-invited account in UnprocessedAccounts, got {resp!r}"
    )
    reason = next(u["Reason"] for u in unprocessed if u["AccountId"] == never_invited_account_id)
    assert reason, f"expected a non-empty Reason for the unprocessed account, got {resp!r}"


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


def _fake_account_id(ctx, exclude: set[str] | None = None) -> str:
    import random

    real_account = ctx.client("sts").get_caller_identity()["Account"]
    exclude = exclude or set()
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
