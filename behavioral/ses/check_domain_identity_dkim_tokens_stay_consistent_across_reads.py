"""domain-identity-dkim-tokens-stay-consistent-across-reads."""
from __future__ import annotations

import base64
import binascii
import string
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-identity-dkim-tokens-stay-consistent-across-reads"
GROUP = "identities"
SERVICES = ["ses"]

_DKIM_TOKEN_ALPHABET = set(string.ascii_lowercase + string.digits)
_DKIM_TOKEN_LEN = 32
_POLL_ATTEMPTS = 12
_POLL_DELAY_S = 2.5

def _all_identities(ses) -> set[str]:
    """Every SES identity in the account, paginated: other identities can push ours off page one."""
    found: set[str] = set()
    for page in ses.get_paginator("list_identities").paginate():
        found.update(page["Identities"])
    return found


def _ignore_missing(fn) -> None:
    fn()


def _dkim_attributes(ses, identity: str) -> dict:
    return ses.get_identity_dkim_attributes(Identities=[identity])["DkimAttributes"][identity]


def _await_dkim_enabled(ses, identity: str, want: bool) -> dict:
    """Poll until DkimEnabled reaches `want`."""
    attrs = {}
    for _ in range(_POLL_ATTEMPTS):
        attrs = _dkim_attributes(ses, identity)
        if attrs["DkimEnabled"] is want:
            return attrs
        time.sleep(_POLL_DELAY_S)
    raise AssertionError(
        f"DkimEnabled never became {want!r} for {identity!r} within "
        f"{_POLL_ATTEMPTS * _POLL_DELAY_S:.0f}s; last attributes were {attrs!r}"
    )


@tags(
    "axis:happy-path",
    "cap:c1",
    "cap:c4",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """VerifyDomainDkim mints three stable DKIM tokens that GetIdentityDkimAttributes returns
    unchanged across a DkimEnabled toggle, so a published CNAME stays valid; the toggle leaves
    VerificationStatus alone and DeleteIdentity removes the identity from both reads.
    """
    ses = ctx.client("ses")
    domain = ctx.unique_name("sim2real-behav-ses-") + ".example.com"

    verification_token = ses.verify_domain_identity(Domain=domain)["VerificationToken"]
    ctx.on_cleanup(lambda: _ignore_missing(lambda: ses.delete_identity(Identity=domain)))
    try:
        decoded = base64.b64decode(verification_token, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise AssertionError(
            f"VerificationToken {verification_token!r} is not valid base64: {exc}"
        ) from exc
    assert len(decoded) == 32, (
        f"VerificationToken decoded to {len(decoded)} bytes, expected 32"
    )

    attrs = ses.get_identity_verification_attributes(
        Identities=[domain]
    )["VerificationAttributes"][domain]
    assert attrs["VerificationStatus"] == "Pending", (
        f"a new domain identity reports {attrs['VerificationStatus']!r}, expected 'Pending'"
    )
    assert attrs["VerificationToken"] == verification_token, (
        f"GetIdentityVerificationAttributes returned token {attrs['VerificationToken']!r}, but "
        f"VerifyDomainIdentity minted {verification_token!r} — the token must be stored state"
    )

    minted = ses.verify_domain_dkim(Domain=domain)["DkimTokens"]
    assert len(minted) == 3, f"VerifyDomainDkim returned {len(minted)} tokens, expected 3"
    assert len(set(minted)) == 3, f"VerifyDomainDkim returned duplicate tokens: {minted!r}"
    for tok in minted:
        assert len(tok) == _DKIM_TOKEN_LEN, (
            f"DKIM token {tok!r} is {len(tok)} chars, expected {_DKIM_TOKEN_LEN}"
        )
        assert set(tok) <= _DKIM_TOKEN_ALPHABET, (
            f"DKIM token {tok!r} contains characters outside [a-z0-9]; it has to be a valid DNS "
            f"label for a CNAME record"
        )

    enabled = _dkim_attributes(ses, domain)
    assert enabled["DkimEnabled"] is True, (
        f"DkimEnabled is {enabled['DkimEnabled']!r} right after VerifyDomainDkim, expected True"
    )
    assert enabled["DkimVerificationStatus"] == "Pending", (
        f"DkimVerificationStatus is {enabled['DkimVerificationStatus']!r}, expected 'Pending' — "
        f"no CNAME was published, so it must not report success"
    )
    # Compared as sets: the API documents no token order.
    assert sorted(enabled["DkimTokens"]) == sorted(minted), (
        f"GetIdentityDkimAttributes returned {enabled['DkimTokens']!r} but VerifyDomainDkim "
        f"minted {minted!r}; the tokens must be the same three values"
    )

    ses.set_identity_dkim_enabled(Identity=domain, DkimEnabled=False)
    disabled = _await_dkim_enabled(ses, domain, False)
    assert sorted(disabled["DkimTokens"]) == sorted(minted), (
        f"disabling DKIM changed the tokens to {disabled['DkimTokens']!r}; they must survive the "
        f"toggle so a published CNAME stays valid"
    )
    still = ses.get_identity_verification_attributes(
        Identities=[domain]
    )["VerificationAttributes"][domain]
    assert still["VerificationStatus"] == "Pending", (
        f"toggling DKIM moved the identity's own VerificationStatus to "
        f"{still['VerificationStatus']!r}; the two are independent"
    )

    ses.set_identity_dkim_enabled(Identity=domain, DkimEnabled=True)
    reenabled = _await_dkim_enabled(ses, domain, True)
    assert sorted(reenabled["DkimTokens"]) == sorted(minted), (
        f"re-enabling DKIM changed the tokens to {reenabled['DkimTokens']!r}, expected {minted!r}"
    )

    assert domain in _all_identities(ses), f"{domain!r} is missing from ListIdentities"

    ses.delete_identity(Identity=domain)
    assert domain not in _all_identities(ses), (
        f"{domain!r} is still in ListIdentities after DeleteIdentity"
    )
    gone = ses.get_identity_verification_attributes(Identities=[domain])
    assert gone["VerificationAttributes"] == {}, (
        f"a deleted identity still has verification attributes "
        f"{gone['VerificationAttributes']!r} — gone must mean gone on both reads"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
