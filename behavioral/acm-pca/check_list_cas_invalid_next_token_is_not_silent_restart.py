"""list-cas-invalid-next-token-is-not-silent-restart."""
from __future__ import annotations

import base64
from botocore.exceptions import ClientError
from behavioral_harness import tags

CHECK = "list-cas-invalid-next-token-is-not-silent-restart"
GROUP = 'overly-permissive'
SERVICES = ['acm-pca']

_INVALID_TOKEN_MESSAGE = (
    "The NextToken you provided is invalid. Use a token returned by ListCertificateAuthorities."
)


def _err(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises.

    An unexpected success raises, so acceptance cannot pass as an ordinary code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected InvalidNextTokenException but the call SUCCEEDED: {result!r}")


def _arns(page):
    return [ca["Arn"] for ca in page.get("CertificateAuthorities", [])]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A NextToken acm-pca did not mint is refused with InvalidNextTokenException, never answered
    with page one again (a NextToken loop would never end), while a genuine token advances the
    cursor to a disjoint page."""
    pca = ctx.client("acm-pca")

    first = pca.list_certificate_authorities(MaxResults=1)
    first_arns = _arns(first)
    assert len(first_arns) <= 1, (
        f"MaxResults=1 returned {len(first_arns)} authorities: {first_arns}"
    )

    bogus_b64 = base64.b64encode(b"sim2real-behav-acm-pca-bogus-cursor").decode("ascii")
    code = _err(lambda: pca.list_certificate_authorities(MaxResults=1, NextToken=bogus_b64))
    assert code == ("InvalidNextTokenException", _INVALID_TOKEN_MESSAGE), (
        f"a NextToken acm-pca never minted must be refused with "
        f"InvalidNextTokenException, got {code!r}"
    )

    # A non-base64 token gets the same refusal as a well-encoded but unminted one.
    code_raw = _err(
        lambda: pca.list_certificate_authorities(MaxResults=1, NextToken="not-a-token-at-all")
    )
    assert code_raw == ("InvalidNextTokenException", _INVALID_TOKEN_MESSAGE), (
        f"a non-base64 NextToken must be refused with InvalidNextTokenException, "
        f"got {code_raw!r}"
    )

    leaked = None
    try:
        leaked = pca.list_certificate_authorities(MaxResults=1, NextToken=bogus_b64)
    except ClientError:
        leaked = None
    assert leaked is None, (
        f"an invalid NextToken returned HTTP 200 with a page instead of erroring: "
        f"{_arns(leaked)}; the cursor was silently discarded and the listing restarted"
    )

    # Only runs when the account already holds two or more CAs; creating one costs a
    # metered private CA.
    token = first.get("NextToken")
    if token:
        second = pca.list_certificate_authorities(MaxResults=1, NextToken=token)
        second_arns = _arns(second)
        assert len(second_arns) <= 1, (
            f"MaxResults=1 second page returned {len(second_arns)} authorities: {second_arns}"
        )
        assert not (set(first_arns) & set(second_arns)), (
            f"page 2 repeated an authority from page 1: page1={first_arns} "
            f"page2={second_arns}; the NextToken did not advance the cursor"
        )
        everything = set()
        paginator = pca.get_paginator("list_certificate_authorities")
        for page in paginator.paginate():
            everything.update(_arns(page))
        for arn in set(first_arns) | set(second_arns):
            assert arn in everything, (
                f"paged listing returned {arn!r}, absent from the full enumeration"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
