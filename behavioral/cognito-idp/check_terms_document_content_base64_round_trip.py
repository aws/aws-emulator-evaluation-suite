"""terms-document-content-base64-round-trip."""
from __future__ import annotations

import base64
import os

from behavioral_harness import tags

CHECK = "terms-document-content-base64-round-trip"
GROUP = "representation"
SERVICES = ["cognito-idp"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A terms URL carrying a base64 payload in its query reads back byte for byte from CreateTerms and
    DescribeTermsByClient, and the payload decodes to the original bytes."""
    cognito = ctx.client("cognito-idp")

    pool_id = cognito.create_user_pool(
        PoolName=ctx.unique_name("sim2real-termspool-"),
        UserPoolTags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-termspool"},
    )["UserPool"]["Id"]
    ctx.on_cleanup(lambda: cognito.delete_user_pool(UserPoolId=pool_id))

    client_id = cognito.create_user_pool_client(
        UserPoolId=pool_id, ClientName=ctx.unique_name("sim2real-termsclient-")
    )["UserPoolClient"]["ClientId"]

    raw_blob = os.urandom(300)
    # URL-safe base64 (no '+', '/') so the payload survives as a literal URL
    # query-string value; keep the '=' padding to also exercise that a
    # reserved-looking character is preserved unmangled.
    content_b64 = base64.urlsafe_b64encode(raw_blob).decode("ascii")
    terms_url = f"https://example.com/terms?content={content_b64}"

    created = cognito.create_terms(
        UserPoolId=pool_id,
        ClientId=client_id,
        TermsName="terms-of-use",
        TermsSource="LINK",
        Enforcement="NONE",
        Links={"cognito:default": terms_url},
    )["Terms"]
    ctx.on_cleanup(lambda: cognito.delete_terms(UserPoolId=pool_id, TermsId=created["TermsId"]))

    assert created["Links"]["cognito:default"] == terms_url, "CreateTerms response mangled the terms URL"

    fetched = cognito.describe_terms_by_client(
        ClientId=client_id, UserPoolId=pool_id, TermsName="terms-of-use"
    )["Terms"]

    assert fetched["Links"]["cognito:default"] == terms_url, (
        "DescribeTermsByClient did not return the terms URL byte-for-byte"
    )
    fetched_b64 = fetched["Links"]["cognito:default"].split("content=", 1)[1]
    assert base64.urlsafe_b64decode(fetched_b64) == raw_blob, (
        "decoded terms content no longer matches the original bytes after the storage round-trip"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
