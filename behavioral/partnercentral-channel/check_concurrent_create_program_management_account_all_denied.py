"""concurrent-create-program-management-account-all-denied."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-create-program-management-account-all-denied"
GROUP = "concurrency"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"
BENEFIT_DENIED = (
    "This action requires an active AWS Partner benefit. Register as an AWS Partner "
    "if you haven't already, or contact AWS Partner Central Support."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Five concurrent well-formed CreateProgramManagementAccount calls from a caller without an active
    AWS Partner benefit are all refused with the exact entitlement AccessDeniedException, and
    ListProgramManagementAccounts is denied the same way."""
    client = ctx.client("partnercentral-channel")

    positive = client.list_channel_handshakes(
        handshakeType="PROGRAM_MANAGEMENT_ACCOUNT",
        catalog=CATALOG,
        participantType="SENDER",
        maxResults=10,
    )
    assert isinstance(positive.get("items"), list), positive

    def attempt(i):
        from botocore.exceptions import ClientError

        try:
            client.create_program_management_account(
                catalog=CATALOG,
                program="SOLUTION_PROVIDER",
                displayName=ctx.unique_name(f"sim2real-race-{i}-")[:30],
                accountId=_FOREIGN_ACCOUNT,
            )
            return ("ok", i, None, None)
        except ClientError as exc:
            return (
                "err",
                i,
                exc.response["Error"]["Code"],
                exc.response["Error"].get("Message"),
            )

    with ThreadPoolExecutor(max_workers=5) as pool:
        results = list(pool.map(attempt, range(5)))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "err"]

    assert len(successes) == 0, f"expected zero winners without partner benefit, got {results}"
    assert len(failures) == 5, f"expected all 5 concurrent attempts to fail, got {results}"
    assert all(code == "AccessDeniedException" for (_, _, code, _) in failures), results
    assert all(msg == BENEFIT_DENIED for (_, _, _, msg) in failures), results

    def _independent_read():
        client.list_program_management_accounts(
            catalog=CATALOG, accountIds=[_FOREIGN_ACCOUNT], maxResults=100
        )

    read_code, read_msg = _error_code(_independent_read)
    assert read_code == "AccessDeniedException", read_code
    assert read_msg == BENEFIT_DENIED, read_msg


# A documentation placeholder account id: a made-up id could be a real account someone else owns.
_FOREIGN_ACCOUNT = "111122223333"


def _error_code(fn):
    """Call fn(); return its botocore Error code and message. An unexpected SUCCESS raises,
    so a target that accepts a call real AWS denies cannot pass as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS denies this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
