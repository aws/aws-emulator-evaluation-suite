"""get-open-id-connect-provider-contract."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "get-open-id-connect-provider-contract"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetOpenIDConnectProvider returns the provider's scheme-stripped Url, its ClientIDList, at least
    one 40-hex thumbprint and a CreateDate; an unknown provider ARN fails with NoSuchEntity and its
    exact message."""
    iam = ctx.client("iam")

    # The check's own user pool is the issuer, so CreateOpenIDConnectProvider fetches its
    # thumbprint from a host the target serves, without a root CA thumbprint computed here.
    url = _user_pool_issuer(ctx)
    client_id = "sts.amazonaws.com"

    created = iam.create_open_id_connect_provider(
        Url=url, ClientIDList=[client_id], Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    provider_arn = created["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn))

    resp = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    # AWS strips the scheme from the stored/returned Url.
    expected_url = url.removeprefix("https://")
    assert resp["Url"] == expected_url, f"expected scheme-stripped Url {expected_url!r}, got {resp['Url']!r}"
    assert resp["ClientIDList"] == [client_id], f"expected ClientIDList {[client_id]!r}, got {resp['ClientIDList']!r}"
    thumbprints = resp["ThumbprintList"]
    assert isinstance(thumbprints, list) and len(thumbprints) >= 1, f"expected a non-empty ThumbprintList, got {thumbprints!r}"
    assert all(
        isinstance(t, str) and len(t) == 40 and all(c in "0123456789abcdefABCDEF" for c in t) for t in thumbprints
    ), f"expected each thumbprint to be a 40-char hex SHA-1 digest, got {thumbprints!r}"
    assert "CreateDate" in resp, f"expected CreateDate in response, got keys {sorted(resp)!r}"

    bogus_arn = provider_arn.rsplit("/", 1)[0] + "/does-not-exist.example.com"
    code, message = _error(lambda: iam.get_open_id_connect_provider(OpenIDConnectProviderArn=bogus_arn))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for missing provider, got {code}"
    expected = f"OpenIDConnect Provider not found for arn {bogus_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _user_pool_issuer(ctx) -> str:
    """The issuer URL of a Cognito user pool this check owns, from CreateUserPool's own answer.

    An OIDC issuer every target serves, so no third-party identity provider is named or contacted.
    """
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-userpool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return f"https://cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"


def _error(fn):
    """(code, message) of the ClientError fn raises; a success raises AssertionError."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
