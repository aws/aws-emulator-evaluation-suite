"""suppressed-destination-invalid-reason-rejected."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "suppressed-destination-invalid-reason-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutSuppressedDestination with Reason SPAM is rejected with BadRequestException and the exact enum message
    and adds nothing, while BOUNCE is accepted; on a sandboxed account even BOUNCE fails with the exact
    sandbox message and adds nothing.
    """
    sesv2 = ctx.client("sesv2")
    account = sesv2.get_account()

    if account.get("ProductionAccessEnabled") is False:
        _assert_sandbox_blocks_every_reason(ctx, sesv2)
        return

    bad_address = f"{ctx.unique_name('sim2real-suppress-bad')}@example.com"
    good_address = f"{ctx.unique_name('sim2real-suppress-good')}@example.com"

    sesv2.put_suppressed_destination(EmailAddress=good_address, Reason="BOUNCE")
    ctx.on_cleanup(lambda: sesv2.delete_suppressed_destination(EmailAddress=good_address))
    fetched = sesv2.get_suppressed_destination(EmailAddress=good_address)["SuppressedDestination"]
    assert fetched["Reason"] == "BOUNCE", f"expected Reason BOUNCE, got {fetched.get('Reason')!r}"

    code, msg = _error(
        lambda: sesv2.put_suppressed_destination(EmailAddress=bad_address, Reason="SPAM")
    )
    assert code == "BadRequestException", f"expected BadRequestException for Reason=SPAM, got {code!r}"
    expected_msg = (
        "1 validation error detected: Value at 'reason' failed to satisfy constraint: "
        "Member must satisfy enum value set: [BOUNCE, COMPLAINT]"
    )
    assert msg == expected_msg, f"expected message {expected_msg!r}, got {msg!r}"

    # effect absent: the invalid request never created a suppression entry
    not_found_code, not_found_msg = _error(
        lambda: sesv2.get_suppressed_destination(EmailAddress=bad_address)
    )
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException for the never-created bad_address, got {not_found_code!r}"
    )
    expected_nf = _not_on_list(bad_address)
    assert not_found_msg == expected_nf, f"expected message {expected_nf!r}, got {not_found_msg!r}"


def _assert_sandbox_blocks_every_reason(ctx, sesv2) -> None:
    address = f"{ctx.unique_name('sim2real-suppress-sandbox')}@example.com"

    # positive control: a read-only call that needs no production access proves
    # credentials and region are otherwise healthy for sesv2.
    sesv2.list_suppressed_destinations(PageSize=1)

    err = _expect_client_error(
        lambda: sesv2.put_suppressed_destination(EmailAddress=address, Reason="BOUNCE")
    )
    error = err.response.get("Error", {})
    assert error.get("Code") == "BadRequestException", (
        f"expected BadRequestException for a sandboxed account, got {error.get('Code')!r}"
    )
    assert error.get("Message") == "Your account is still in the sandbox.", (
        f"expected the sandbox-access message, got {error.get('Message')!r}"
    )

    not_found_code, not_found_msg = _error(
        lambda: sesv2.get_suppressed_destination(EmailAddress=address)
    )
    assert not_found_code == "NotFoundException", (
        f"expected NotFoundException for the never-created address, got {not_found_code!r}"
    )
    expected_nf = _not_on_list(address)
    assert not_found_msg == expected_nf, f"expected message {expected_nf!r}, got {not_found_msg!r}"


def _not_on_list(address: str) -> str:
    return f"Email address {address} does not exist on your suppression list."


def _expect_client_error(fn) -> ClientError:
    try:
        result = fn()
    except ClientError as err:
        return err
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _error(fn) -> tuple[str, str]:
    """Call fn(); return the botocore (Error.Code, Error.Message) it is refused with. An unexpected
    SUCCESS raises."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
