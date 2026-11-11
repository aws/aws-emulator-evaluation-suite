"""terms-document-content-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "terms-document-content-round-trip"
GROUP = "representation"
SERVICES = ["cognito-idp"]

# CreateTerms.Links stores a per-language URL string (not a document body); its value
# pattern allows any Letter/Mark/Symbol/Number/Punctuation Unicode codepoint (no whitespace).
_UNICODE_LINK = "https://\u4f8b\u3048.example.com/\u6761\u6b3e-Bedingungen-\u0394\u03bf\u03ba\u03b9\u03bc\u03ae?v=1"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateTerms with a unicode terms-document link is returned with identical content
    (same key and byte-identical unicode value) by DescribeTermsByClient."""
    idp = ctx.client("cognito-idp")

    pool_id = idp.create_user_pool(
        PoolName=ctx.unique_name("sim2real-termspool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))

    client_id = idp.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-termsclient-")
    )["UserPoolClient"]["ClientId"]

    links = {"cognito:default": _UNICODE_LINK}
    created = idp.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links=links,
    )["Terms"]
    terms_id = created["TermsId"]
    ctx.on_cleanup(lambda: idp.delete_terms(UserPoolId=pool_id, TermsId=terms_id))

    assert created["Links"] == links, f"CreateTerms echoed {created['Links']!r}, expected {links!r}"

    fetched = idp.describe_terms_by_client(
        ClientId=client_id, UserPoolId=pool_id, TermsName="terms-of-use"
    )["Terms"]
    assert fetched["Links"] == links, (
        f"DescribeTermsByClient returned {fetched['Links']!r}, expected {links!r}"
    )
    assert fetched["Links"]["cognito:default"] == _UNICODE_LINK, (
        f"unicode terms link mangled in storage round-trip: got {fetched['Links']['cognito:default']!r}, "
        f"expected {_UNICODE_LINK!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
