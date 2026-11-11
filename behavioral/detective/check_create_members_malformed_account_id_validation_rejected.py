"""create-members-malformed-account-id-validation-rejected."""
from __future__ import annotations

import uuid

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-members-malformed-account-id-validation-rejected"
GROUP = "overly-permissive"
SERVICES = ["detective"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:detective-graph")
def run(ctx) -> None:
    """CreateMembers with a 12-character AccountId holding a non-digit fails with ValidationException
    "Account.AccountId did not match the pattern." and records no member, while a 12-digit id is recorded."""
    d = ctx.client("detective")
    arn = d.create_graph()["GraphArn"]
    # An account administers at most one behavior graph per Region; CreateGraph returns that
    # graph, so it is left in place.

    # 12 characters satisfies the SDK's length-only client-side check, but the trailing letter
    # violates the service's own ^[0-9]+$ pattern -- so this request reaches the service and is
    # rejected there.
    malformed_account = "12345678901A"
    code, message = _error(
        lambda: d.create_members(
            GraphArn=arn,
            Accounts=[{"AccountId": malformed_account, "EmailAddress": "sim2real-detective@example.com"}],
            DisableEmailNotification=True,
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == "Account.AccountId did not match the pattern.", f"unexpected message: {message!r}"

    members_after = _list_all_members(d, arn)
    member_ids_after = [m["AccountId"] for m in members_after]
    assert malformed_account not in member_ids_after, (
        f"malformed account id must not appear as a member: {members_after!r}"
    )

    # Positive control: a well-formed account id in an otherwise identical request succeeds.
    valid_account = _fake_account_id(ctx)
    valid_email = f"sim2real-detective-{uuid.uuid4().hex[:10]}@example.com"
    resp = d.create_members(
        GraphArn=arn,
        Accounts=[{"AccountId": valid_account, "EmailAddress": valid_email}],
        DisableEmailNotification=True,
    )
    ctx.on_cleanup(lambda: _delete_members_quietly(d, arn, [valid_account]))
    assert resp["Members"][0]["AccountId"] == valid_account
    assert resp.get("UnprocessedAccounts") == []


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


def _delete_graph_quietly(d, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        d.delete_graph(GraphArn=arn)
    except ClientError:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
