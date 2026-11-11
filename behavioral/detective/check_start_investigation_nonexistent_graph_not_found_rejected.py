"""start-investigation-nonexistent-graph-not-found-rejected."""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "start-investigation-nonexistent-graph-not-found-rejected"
GROUP = "overly-permissive"
SERVICES = ["detective"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """StartInvestigation on a well-formed GraphArn that was never created fails with ResourceNotFoundException
    "Graph Not Found. Please check the graphArn provided" and creates no investigation, while CreateMembers
    on the account's real graph succeeds."""
    d = ctx.client("detective")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    never_created_graph_arn = (
        f"arn:aws:detective:{ctx.region}:{account_id}:graph:{uuid.uuid4().hex}"
    )
    entity_arn = f"arn:aws:iam::{account_id}:role/sim2real-detective-never-created-role"

    scope_end = datetime.now(timezone.utc)
    scope_start = scope_end - timedelta(hours=4)

    code, message = _error(
        lambda: d.start_investigation(
            GraphArn=never_created_graph_arn,
            EntityArn=entity_arn,
            ScopeStartTime=scope_start,
            ScopeEndTime=scope_end,
        )
    )
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "Graph Not Found. Please check the graphArn provided", f"unexpected message: {message!r}"

    # Positive control: a real, valid mutating call against an actual graph in this account
    # still works, proving the API surface is not universally rejecting requests. The terminal
    # assertion is an independent GetMembers read, not the CreateMembers response echo.
    real_arn = _create_graph_with_retry(d)
    # An account administers at most one behavior graph per Region; CreateGraph returns that
    # graph, so it is left in place.
    fake_account = _fake_account_id(ctx)
    email = f"sim2real-detective-{uuid.uuid4().hex[:10]}@example.com"
    d.create_members(
        GraphArn=real_arn,
        Accounts=[{"AccountId": fake_account, "EmailAddress": email}],
        DisableEmailNotification=True,
    )
    ctx.on_cleanup(lambda: _delete_members_quietly(d, real_arn, [fake_account]))

    details = d.get_members(GraphArn=real_arn, AccountIds=[fake_account])["MemberDetails"]
    assert len(details) == 1, f"expected exactly one member for {fake_account!r}, got {details!r}"
    assert details[0]["AccountId"] == fake_account, (
        f"expected AccountId {fake_account!r}, got {details[0]['AccountId']!r}"
    )


def _create_graph_with_retry(d, retries: int = 8, base_delay: float = 5.0) -> str:
    import time

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


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
