"""suppressed-destination-put-get-delete-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "suppressed-destination-put-get-delete-lifecycle"
GROUP = "state-machine"
SERVICES = ["sesv2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """In the SES sandbox, PutSuppressedDestination fails BadRequestException and the address stays
    absent; with production access, put reads back its Reason and delete yields NotFoundException.
    """
    sesv2 = ctx.client("sesv2")
    address = f"{ctx.unique_name('sim2real-suppress')}@example.com"

    acct = sesv2.get_account()
    assert "ProductionAccessEnabled" in acct, (
        f"GetAccount must report ProductionAccessEnabled, got keys {sorted(acct)}"
    )

    if not acct["ProductionAccessEnabled"]:
        err = _client_error(lambda: sesv2.put_suppressed_destination(EmailAddress=address, Reason="BOUNCE"))
        code = err.response["Error"]["Code"]
        msg = err.response["Error"].get("Message") or ""
        assert code == "BadRequestException", (
            f"a sandboxed PutSuppressedDestination must be refused with BadRequestException, "
            f"got {code!r}: {msg!r}"
        )
        assert msg == "Your account is still in the sandbox.", (
            f"the refusal must say why -- real AWS answers 'Your account is still in the "
            f"sandbox.'; got {msg!r}"
        )

        after = _client_error(lambda: sesv2.get_suppressed_destination(EmailAddress=address))
        assert after.response["Error"]["Code"] == "NotFoundException", (
            f"a refused PutSuppressedDestination must leave {address!r} unsuppressed, "
            f"got {after.response['Error']!r}"
        )
        assert after.response["Error"].get("Message") == _not_on_list(address), (
            f"expected message {_not_on_list(address)!r}, got {after.response['Error']!r}"
        )
        return

    state = {"deleted": False}
    ctx.on_cleanup(
        lambda: None if state["deleted"] else sesv2.delete_suppressed_destination(EmailAddress=address)
    )

    sesv2.put_suppressed_destination(EmailAddress=address, Reason="BOUNCE")
    fetched = sesv2.get_suppressed_destination(EmailAddress=address)["SuppressedDestination"]
    assert fetched["EmailAddress"].lower() == address.lower(), (
        f"expected EmailAddress {address.lower()!r}, got {fetched['EmailAddress'].lower()!r}"
    )
    assert fetched["Reason"] == "BOUNCE", f"expected Reason 'BOUNCE', got {fetched['Reason']!r}"
    assert "LastUpdateTime" in fetched, f"GetSuppressedDestination response missing LastUpdateTime: {fetched!r}"

    sesv2.delete_suppressed_destination(EmailAddress=address)
    state["deleted"] = True

    gone = _client_error(lambda: sesv2.get_suppressed_destination(EmailAddress=address))
    assert gone.response["Error"]["Code"] == "NotFoundException", (
        f"GetSuppressedDestination after delete must answer NotFoundException, "
        f"got {gone.response['Error']!r}"
    )
    assert gone.response["Error"].get("Message") == _not_on_list(address), (
        f"expected message {_not_on_list(address)!r}, got {gone.response['Error']!r}"
    )


def _client_error(fn) -> ClientError:
    try:
        fn()
    except ClientError as exc:
        return exc
    raise AssertionError("expected the call to be refused, but it succeeded")


def _not_on_list(address: str) -> str:
    return f"Email address {address} does not exist on your suppression list."


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
