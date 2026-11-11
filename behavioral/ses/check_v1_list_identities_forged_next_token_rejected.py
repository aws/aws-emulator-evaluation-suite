"""v1-list-identities-forged-next-token-rejected."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "v1-list-identities-forged-next-token-rejected"
GROUP = 'identity-v2'
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
    """A forged NextToken on v1 ListIdentities is refused with InvalidParameterValue rather than served
    as page one, and a tokenless listing still includes the created identity afterward.
    """
    v1 = ctx.client('ses')
    domain = ctx.unique_name('sim2real-behav-v1tok-') + '.example.com'
    v1.verify_domain_identity(Domain=domain)
    ctx.on_cleanup(lambda: v1.delete_identity(Identity=domain))

    control = v1.list_identities(IdentityType='Domain', MaxItems=1000)
    assert domain in (control.get('Identities') or []), (
        f"positive control failed: {domain!r} missing from a plain ListIdentities read: {control!r}"
    )

    forged = 'c2ltMnJlYWwtZm9yZ2VkLXYxLXRva2Vu'
    err = _error(lambda: v1.list_identities(NextToken=forged))
    expected = ('InvalidParameterValue', f"Invalid NextToken <{forged}>.")
    assert err == expected, (
        f"a forged v1 NextToken must be refused with {expected!r}, got {err!r}"
    )

    after = v1.list_identities(IdentityType='Domain', MaxItems=1000)
    assert domain in (after.get('Identities') or []), (
        f"{domain!r} disappeared from ListIdentities after the rejected forged-token call: {after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
