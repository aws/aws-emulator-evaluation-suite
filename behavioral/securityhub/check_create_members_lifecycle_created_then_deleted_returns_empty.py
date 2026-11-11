"""create-members-lifecycle-created-then-deleted-returns-empty."""
from __future__ import annotations

import hashlib

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "create-members-lifecycle-created-then-deleted-returns-empty"
GROUP = "state"
SERVICES = ["securityhub"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:securityhub")
def run(ctx) -> None:
    """CreateMembers records MemberStatus=Created; after DeleteMembers, GetMembers for it comes back
    empty (neither a Member nor an UnprocessedAccount) rather than resurrecting the deleted record."""
    sh = ctx.client("securityhub")
    _ensure_hub_enabled(sh)
    fake_account_id = _fake_account_id(ctx)

    resp = sh.create_members(
        AccountDetails=[{"AccountId": fake_account_id, "Email": f"sim2real+{fake_account_id}@example.com"}]
    )
    assert resp["UnprocessedAccounts"] == [], resp

    def _cleanup():
        try:
            sh.delete_members(AccountIds=[fake_account_id])
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    got = sh.get_members(AccountIds=[fake_account_id])
    assert got["UnprocessedAccounts"] == [], f"expected no unprocessed accounts, got {got['UnprocessedAccounts']}"
    assert len(got["Members"]) == 1, f"expected exactly 1 member for {fake_account_id}, got {got['Members']}"
    assert got["Members"][0]["MemberStatus"] == "Created", (
        f"expected MemberStatus=Created, got {got['Members'][0]['MemberStatus']!r}"
    )

    sh.delete_members(AccountIds=[fake_account_id])

    # Effect absent: the deleted member is gone from ListMembers.
    remaining_ids = {m["AccountId"] for m in sh.list_members()["Members"]}
    assert fake_account_id not in remaining_ids, f"expected {fake_account_id} absent from ListMembers, got {remaining_ids}"

    # The graded negative outcome: GetMembers for a fully-deleted, unknown account doesn't
    # resurrect a Member record -- Security Hub simply reports it as neither a Member nor an
    # UnprocessedAccount (an empty response), not the "Created" record from before deletion.
    got_after = sh.get_members(AccountIds=[fake_account_id])
    assert got_after["Members"] == [], got_after
    assert got_after["UnprocessedAccounts"] == [], got_after


def _ensure_hub_enabled(sh):
    from botocore.exceptions import ClientError

    try:
        sh.enable_security_hub(EnableDefaultStandards=False)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceConflictException":
            raise


def _fake_account_id(ctx):
    h = hashlib.sha256(ctx.unique_name("sim2real-member").encode()).hexdigest()
    digits = "9" + "".join(c for c in h if c.isdigit())
    return digits[:12]


def _error_code(fn):
    from botocore.exceptions import ClientError

    try:
        fn()
        return None
    except ClientError as exc:
        return exc.response["Error"]["Code"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)


