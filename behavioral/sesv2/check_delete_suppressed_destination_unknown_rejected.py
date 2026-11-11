"""delete-suppressed-destination-unknown-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-suppressed-destination-unknown-rejected"
GROUP = "error-semantics"
SERVICES = ["sesv2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteSuppressedDestination for an address never suppressed answers NotFoundException with its exact
    message; a suppressed address is deleted and reads back absent, or on a sandboxed account
    PutSuppressedDestination fails with the sandbox BadRequestException and stores nothing.
    """
    sesv2 = ctx.client("sesv2")
    never_suppressed = f"{ctx.unique_name('sim2real-suppress-never')}@example.com"

    err = _error(
        lambda: sesv2.delete_suppressed_destination(EmailAddress=never_suppressed)
    )
    expected = (
        "NotFoundException",
        f"Email address {never_suppressed} does not exist on your suppression list.",
    )
    assert err == expected, f"expected {expected!r}, got {err!r}"

    account = sesv2.get_account()
    real_address = f"{ctx.unique_name('sim2real-suppress-real')}@example.com"

    expected_absent = (
        "NotFoundException",
        f"Email address {real_address} does not exist on your suppression list.",
    )
    if not account["ProductionAccessEnabled"]:
        put_err = _error(
            lambda: sesv2.put_suppressed_destination(EmailAddress=real_address, Reason="BOUNCE")
        )
        expected_sandbox = ("BadRequestException", "Your account is still in the sandbox.")
        assert put_err == expected_sandbox, (
            f"expected {expected_sandbox!r} for a sandboxed account, got {put_err!r}"
        )
        never_created = _error(
            lambda: sesv2.get_suppressed_destination(EmailAddress=real_address)
        )
        assert never_created == expected_absent, (
            f"expected the rejected PutSuppressedDestination to leave no destination, got {never_created!r}"
        )
        return

    ctx.on_cleanup(lambda: _delete_if_present(sesv2, real_address))
    sesv2.put_suppressed_destination(EmailAddress=real_address, Reason="BOUNCE")
    sesv2.delete_suppressed_destination(EmailAddress=real_address)
    after = _error(
        lambda: sesv2.get_suppressed_destination(EmailAddress=real_address)
    )
    assert after == expected_absent, f"expected {expected_absent!r} after delete, got {after!r}"


def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as err:
        return (err.response["Error"]["Code"], err.response["Error"].get("Message"))
    raise AssertionError(f"expected a ClientError, the call succeeded with {result!r}")


def _delete_if_present(sesv2, address: str) -> None:
    """Teardown: remove the address, tolerating its absence."""
    try:
        sesv2.delete_suppressed_destination(EmailAddress=address)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
