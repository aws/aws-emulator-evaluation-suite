"""list-identities-invalid-identity-type-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-identities-invalid-identity-type-rejected"
GROUP = 'identity'
SERVICES = ['ses']


def _error(fn):
    """Call fn(); return its botocore error (Code, Message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response['Error']['Code'], exc.response['Error'].get('Message')
    raise AssertionError(f"expected the call to be refused, but it succeeded with {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListIdentities rejects an IdentityType outside {EmailAddress, Domain} with a server-side
    ValidationError, rather than silently ignoring the filter or treating it as "no filter".
    """
    ses = ctx.client('ses')
    email = f"{ctx.unique_name('sim2real-behav-badtype-')}@example.com"
    ses.verify_email_identity(EmailAddress=email)
    ctx.on_cleanup(lambda: ses.delete_identity(Identity=email))

    # Positive control: a valid IdentityType still works and includes what we just created.
    control = ses.list_identities(IdentityType='EmailAddress', MaxItems=1000)
    assert email in (control.get('Identities') or []), (
        f"positive control failed: {email!r} missing from a valid-filter ListIdentities read: {control!r}"
    )

    # botocore does not validate IdentityType client-side, so this reaches the server.
    err = _error(lambda: ses.list_identities(IdentityType='Bogus'))
    expected = (
        'ValidationError',
        "1 validation error detected: Value at 'identityType' failed to satisfy "
        "constraint: Member must satisfy enum value set: [Domain, EmailAddress]",
    )
    assert err == expected, (
        f"expected {expected!r} for IdentityType='Bogus', got {err!r}"
    )

    # Effect absent: the account's identity listing is unchanged by the rejected call.
    after = ses.list_identities(IdentityType='EmailAddress', MaxItems=1000)
    assert email in (after.get('Identities') or []), (
        f"{email!r} disappeared from ListIdentities after the rejected invalid-type call: {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
