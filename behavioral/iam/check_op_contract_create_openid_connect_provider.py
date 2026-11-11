"""op-contract-create-openid-connect-provider."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "op-contract-create-openid-connect-provider"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOpenIDConnectProvider without a ThumbprintList stores the scheme-stripped Url and at
    least one 40-hex thumbprint IAM fetched; a duplicate Url fails with EntityAlreadyExists and its
    exact message and leaves the provider's Url and thumbprints unchanged."""
    iam = ctx.client("iam")

    oidc_url = _user_pool_issuer(ctx)

    created = iam.create_open_id_connect_provider(
        Url=oidc_url, Tags=[{"Key": "sim2real", "Value": CHECK}]
    )
    provider_arn = created["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn))

    got = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    assert got["Url"] == oidc_url.removeprefix("https://"), (
        f"expected Url {oidc_url!r} (scheme stripped), got {got['Url']!r}"
    )
    thumbprints = got.get("ThumbprintList", [])
    assert len(thumbprints) >= 1, "expected IAM to auto-fetch a thumbprint"
    for tp in thumbprints:
        assert isinstance(tp, str) and len(tp) == 40 and all(c in "0123456789abcdefABCDEF" for c in tp), (
            f"expected a 40-char hex SHA1 thumbprint, got {tp!r}"
        )

    code, message = _error(lambda: iam.create_open_id_connect_provider(Url=oidc_url))
    assert code == "EntityAlreadyExists", f"expected EntityAlreadyExists, got {code}"
    expected = f"Provider with url {oidc_url} already exists."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the rejected duplicate must not have mutated the original provider
    unchanged = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    assert unchanged["Url"] == got["Url"], "rejected duplicate CreateOpenIDConnectProvider must not change Url"
    assert unchanged["ThumbprintList"] == thumbprints, (
        "rejected duplicate CreateOpenIDConnectProvider must not change ThumbprintList"
    )


def _user_pool_issuer(ctx) -> str:
    """The issuer URL of a Cognito user pool this check owns, from CreateUserPool's own answer.

    An OIDC issuer every target serves, so no third-party identity provider is named or contacted.
    """
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-userpool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return f"https://cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
