"""create-members-invalid-account-id-pattern-rejected."""
from __future__ import annotations

import time
import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-members-invalid-account-id-pattern-rejected"
GROUP = "overly-permissive"
SERVICES = ["detective"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """CreateMembers rejects a 12-char AccountId containing a non-digit; no member is created; a valid one still is."""
    d = ctx.client("detective")
    arn = _create_graph_with_retry(d)
    # NOTE: an account can administer only one behavior graph per Region, so this graph is
    # shared with other checks in the suite run; it is intentionally not deleted here.

    # Exactly 12 characters (passes the SDK's length check) but not all-digits, so the
    # rejection is a genuine server-side pattern validation, not client-side length validation.
    bad_account_id = "1234567890AB"
    assert len(bad_account_id) == 12 and not bad_account_id.isdigit()
    fake_email = f"sim2real-detective-{uuid.uuid4().hex[:10]}@example.com"

    code, message = _error(lambda: d.create_members(
        GraphArn=arn,
        Accounts=[{"AccountId": bad_account_id, "EmailAddress": fake_email}],
        DisableEmailNotification=True,
    ))
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Account.AccountId did not match the pattern.", f"unexpected message: {message!r}"

    # effect absent: nothing was ever created for the malformed id
    listed = _list_all_members(d, arn)
    assert bad_account_id not in [m["AccountId"] for m in listed], f"malformed id must not appear as a member: {listed!r}"

    # positive control: a syntactically-valid account id in the same shape still succeeds
    good_account_id = _fake_account_id(ctx)
    resp = d.create_members(
        GraphArn=arn,
        Accounts=[{"AccountId": good_account_id, "EmailAddress": fake_email}],
        DisableEmailNotification=True,
    )
    ctx.on_cleanup(lambda: _delete_members_quietly(d, arn, [good_account_id]))
    assert resp["UnprocessedAccounts"] == [], f"unexpected UnprocessedAccounts: {resp!r}"
    assert [m["AccountId"] for m in resp["Members"]] == [good_account_id]


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


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
