"""list-members-excludes-never-added-account-2."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-members-excludes-never-added-account-2"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """ListMembers on the account's behavior graph lists an account added with CreateMembers and never an
    account that was not added; other members may exist, so only that one account's absence is asserted."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # An account administers at most one behavior graph per Region; CreateGraph returns that
    # graph, so it is left in place.

    added_account_id = _fake_account_id(ctx)
    added_email = f"sim2real-detective-{uuid.uuid4().hex[:10]}@example.com"
    d.create_members(
        GraphArn=arn,
        Accounts=[{"AccountId": added_account_id, "EmailAddress": added_email}],
        DisableEmailNotification=True,
    )
    ctx.on_cleanup(lambda: _delete_members_quietly(d, arn, [added_account_id]))

    never_added_account = _fake_account_id(ctx, exclude={added_account_id})

    members = _poll_until(
        probe=lambda: _list_all_members(d, arn),
        predicate=lambda members: any(m["AccountId"] == added_account_id for m in members),
        timeout_s=30.0,
        interval_s=2.0,
    )
    member_ids = [m["AccountId"] for m in members]
    assert added_account_id in member_ids, (
        f"positive control: account {added_account_id!r} was added via CreateMembers but did "
        f"not appear in ListMembers: {members!r}"
    )
    assert never_added_account not in member_ids, (
        f"account {never_added_account!r} was never added but appeared in ListMembers: {members!r}"
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


def _list_all_members(d, graph_arn: str) -> list[dict]:
    out: list[dict] = []
    token = None
    while True:
        kwargs = {"NextToken": token} if token else {}
        resp = d.list_members(GraphArn=graph_arn, **kwargs)
        out.extend(resp.get("MemberDetails", []))
        token = resp.get("NextToken")
        if not token:
            break
    return out


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


def _fake_account_id(ctx, exclude: set[str] | None = None) -> str:
    import random

    real_account = ctx.client("sts").get_caller_identity()["Account"]
    excluded = {real_account} | (exclude or set())
    while True:
        candidate = "9" + "".join(str(random.randint(0, 9)) for _ in range(11))
        if candidate not in excluded:
            return candidate


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
