"""create-program-management-account-access-denied-without-partner-benefit."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "create-program-management-account-access-denied-without-partner-benefit"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"
BENEFIT_DENIED = (
    "This action requires an active AWS Partner benefit. Register as an AWS Partner "
    "if you haven't already, or contact AWS Partner Central Support."
)


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateProgramManagementAccount with a clientToken is refused with the exact entitlement
    AccessDeniedException for a caller without an active AWS Partner benefit, identically when repeated
    with the same clientToken."""
    client = ctx.client("partnercentral-channel")

    positive = client.list_channel_handshakes(
        handshakeType="PROGRAM_MANAGEMENT_ACCOUNT",
        catalog=CATALOG,
        participantType="SENDER",
        maxResults=10,
    )
    assert isinstance(positive.get("items"), list), (
        f"expected the positive control (ListChannelHandshakes) to succeed for a "
        f"healthy session, got {positive!r}"
    )

    account_id = _FOREIGN_ACCOUNT
    display_name = ctx.unique_name("sim2real-pma-")[:30]
    client_token = ctx.unique_name("sim2real-pma-token-")

    def _attempt():
        return client.create_program_management_account(
            catalog=CATALOG,
            program="SOLUTION_PROVIDER",
            displayName=display_name,
            accountId=account_id,
            clientToken=client_token,
        )

    code1, msg1 = _error_code_and_message(_attempt)
    assert code1 == "AccessDeniedException", f"expected AccessDeniedException, got {code1}"
    assert msg1 == BENEFIT_DENIED, msg1

    code2, msg2 = _error_code_and_message(_attempt)
    assert code2 == "AccessDeniedException", (
        f"expected the identical clientToken-bearing retry to be denied the same way, "
        f"got {code2}"
    )
    assert msg2 == msg1, f"expected an identical denial message on retry, got {msg2!r} vs {msg1!r}"


# A documentation placeholder account id: a made-up id could be a real account someone else owns.
_FOREIGN_ACCOUNT = "111122223333"


def _error_code_and_message(fn):
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
