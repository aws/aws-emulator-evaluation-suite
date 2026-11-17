"""send-email-tenant-resolution-precedes-sender-verification."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "send-email-tenant-resolution-precedes-sender-verification"
GROUP = "tenant-gating"
SERVICES = ["sesv2", "sts"]

_SIMULATOR_RECIPIENT = "success@simulator.amazonses.com"


def _teardown(undo, *not_found: str):
    """Cleanup running undo(); only the resource's own not_found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message):
    got_code, got_message = _error(fn)
    assert got_code == code, f"expected {code}, got {got_code}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """SendEmail from an unverified sender with a TenantName that names no tenant answers
    NotFoundException naming the tenant and account; with an existing tenant, or with no
    TenantName, the same send answers the one MessageRejected for the unverified sender.
    """
    sesv2 = ctx.client("sesv2")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    live_tenant = ctx.unique_name("sim2real-sesv2gate-tenant-")
    sesv2.create_tenant(TenantName=live_tenant, Tags=[{"Key": "sim2real", "Value": CHECK}])
    ctx.on_cleanup(_teardown(lambda: sesv2.delete_tenant(TenantName=live_tenant), "NotFoundException"))

    # Positive control: the created tenant genuinely resolves through an independent read.
    fetched = sesv2.get_tenant(TenantName=live_tenant)["Tenant"]
    assert fetched["TenantName"] == live_tenant, (
        f"GetTenant({live_tenant!r}) returned TenantName {fetched['TenantName']!r}"
    )

    ghost_tenant = ctx.unique_name("sim2real-sesv2gate-tenant-ghost-")
    # Pin the ghost name to genuine absence, not merely "SendEmail refused it".
    expect_error(
        lambda: sesv2.get_tenant(TenantName=ghost_tenant),
        "NotFoundException",
        f"The requested tenant <{ghost_tenant}> does not exist.",
    )

    sender = ctx.unique_name("sim2real-sesv2gate-sender-") + "@example.com"
    content = {
        "Simple": {
            "Subject": {"Data": "tenant resolution order probe"},
            "Body": {"Text": {"Data": "tenant resolution order probe body"}},
        }
    }

    def _attempt(tenant_name) -> tuple:
        kwargs = dict(
            FromEmailAddress=sender,
            Destination={"ToAddresses": [_SIMULATOR_RECIPIENT]},
            Content=content,
        )
        if tenant_name is not None:
            kwargs["TenantName"] = tenant_name
        return _error(lambda: sesv2.send_email(**kwargs))

    # Leg 1: a tenant name that resolves to nothing is refused before the sender is even looked at.
    ghost_result = _attempt(ghost_tenant)
    assert ghost_result == (
        "NotFoundException",
        f"Tenant {ghost_tenant} for AwsAccountId {account_id} not found.",
    ), f"SendEmail with a nonexistent TenantName returned {ghost_result!r}"

    # Leg 2: an existing tenant leaves only the unverified sender to refuse.
    live_result = _attempt(live_tenant)
    not_verified = (
        "MessageRejected",
        "Email address is not verified. The following identities failed the check in region "
        f"{ctx.region.upper()}: {sender}",
    )
    assert live_result == not_verified, (
        f"SendEmail against a real tenant with an unverified sender returned {live_result!r}, "
        f"expected {not_verified!r}"
    )

    # Leg 3: with no TenantName the send is refused for the sender alone, with the same message.
    no_tenant_result = _attempt(None)
    assert no_tenant_result == not_verified, (
        f"SendEmail with no TenantName at all returned {no_tenant_result!r}, expected the same "
        f"{not_verified!r} the real-tenant call produced"
    )
    assert no_tenant_result == live_result, (
        f"a real tenant and no tenant at all must fail on the identical message once resolution "
        f"clears, but got {live_result!r} vs {no_tenant_result!r}"
    )

    # The ghost tenant's refusal is a distinct code from both legs that cleared resolution.
    assert ghost_result[0] != live_result[0], (
        f"the unresolved-tenant refusal {ghost_result!r} must not share its code with the "
        f"resolved-tenant refusal {live_result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
