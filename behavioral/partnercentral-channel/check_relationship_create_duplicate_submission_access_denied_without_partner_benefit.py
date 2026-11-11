"""relationship-create-duplicate-submission-access-denied-without-partner-benefit."""
from __future__ import annotations


from behavioral_harness import tags

CHECK = "relationship-create-duplicate-submission-access-denied-without-partner-benefit"
GROUP = "overly-permissive"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """The identical CreateRelationship (same clientToken) submitted twice by a caller without an active
    AWS Partner benefit is refused both times with AccessDeniedException and the same partner message,
    and ListRelationships gets a partner AccessDeniedException too."""
    client = ctx.client("partnercentral-channel")
    identity = ctx.client("sts").get_caller_identity()
    assert identity.get("Account"), "expected a resolvable caller identity (STS healthy)"

    fake_pma_id = "pma-1111111111111"
    associated_account_id = _FOREIGN_ACCOUNT
    client_token = ctx.unique_name("sim2real-rel-tok-")[:36]
    display_name = ctx.unique_name("sim2real-rel-")[:30]

    def _attempt_create():
        return client.create_relationship(
            catalog=CATALOG,
            associationType="END_CUSTOMER",
            programManagementAccountIdentifier=fake_pma_id,
            associatedAccountId=associated_account_id,
            displayName=display_name,
            sector="COMMERCIAL",
            clientToken=client_token,
        )

    code1, msg1 = _error_code_and_message(_attempt_create)
    assert code1 == "AccessDeniedException", f"expected AccessDeniedException, got {code1}"
    assert "partner" in (msg1 or "").lower(), msg1

    code2, msg2 = _error_code_and_message(_attempt_create)
    assert code2 == "AccessDeniedException", (
        f"duplicate submission diverged from the first attempt: first={code1} second={code2}"
    )
    assert msg2 == msg1, f"duplicate submission got a different message: {msg1!r} vs {msg2!r}"

    def _attempt_list():
        return client.list_relationships(catalog=CATALOG, maxResults=50)

    code3, msg3 = _error_code_and_message(_attempt_list)
    assert code3 == "AccessDeniedException", (
        f"expected the read path to be gated by the identical entitlement error, got {code3}"
    )
    assert "partner" in (msg3 or "").lower(), msg3


# A documentation placeholder account id: a made-up id could be a real account someone else owns.
_FOREIGN_ACCOUNT = "111122223333"


def _error_code_and_message(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call succeeded: {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
