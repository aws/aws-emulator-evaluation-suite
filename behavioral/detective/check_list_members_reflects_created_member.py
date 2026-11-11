"""list-members-reflects-created-member."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "list-members-reflects-created-member"
GROUP = "state"
SERVICES = ["detective"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """ListMembers (the paginated listing, distinct from the by-id GetMembers) reflects a newly created member."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.

    fake_account_id = _fake_account_id(ctx)
    fake_email = f"sim2real-detective-{uuid.uuid4().hex[:10]}@example.com"
    d.create_members(
        GraphArn=arn,
        Accounts=[{"AccountId": fake_account_id, "EmailAddress": fake_email}],
        DisableEmailNotification=True,
    )
    ctx.on_cleanup(lambda: _delete_members_quietly(d, arn, [fake_account_id]))

    listed = _poll_until(
        probe=lambda: _list_all_members(d, arn),
        predicate=lambda members: any(m["AccountId"] == fake_account_id for m in members),
        timeout_s=30.0,
        interval_s=2.0,
    )
    matches = [m for m in listed if m["AccountId"] == fake_account_id]
    assert len(matches) == 1, f"expected the created member to appear exactly once in ListMembers, got {listed!r}"
    # The fake account ID does not correspond to a real AWS account, so Detective's
    # account/email verification never reaches INVITED for it -- it either stays in
    # VERIFICATION_IN_PROGRESS or settles on VERIFICATION_FAILED.
    assert matches[0]["Status"] in ("VERIFICATION_IN_PROGRESS", "VERIFICATION_FAILED"), (
        f"unexpected status for an unverifiable fake account: {matches[0]!r}"
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


def _fake_account_id(ctx) -> str:
    import random

    real_account = ctx.client("sts").get_caller_identity()["Account"]
    while True:
        candidate = "9" + "".join(str(random.randint(0, 9)) for _ in range(11))
        if candidate != real_account:
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
