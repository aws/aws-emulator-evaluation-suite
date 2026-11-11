"""op-contract-remove-client-id-from-oidc-provider."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-remove-client-id-from-oidc-provider"
GROUP = "error-semantics"
SERVICES = ["iam"]

@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveClientIDFromOpenIDConnectProvider drops one client ID and keeps its sibling; an unknown
    provider ARN is NoSuchEntity with the exact message and does not disturb the real provider."""
    iam = ctx.client("iam")
    client_id = ctx.unique_name("sim2real-oidc-client-")
    sibling_id = ctx.unique_name("sim2real-oidc-sibling-")

    arn = _create_provider(ctx, iam, _user_pool_issuer(ctx), [client_id, sibling_id])

    got = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    assert client_id in got["ClientIDList"], f"expected {client_id} in {got['ClientIDList']}"
    assert sibling_id in got["ClientIDList"], f"expected {sibling_id} in {got['ClientIDList']}"

    iam.remove_client_id_from_open_id_connect_provider(OpenIDConnectProviderArn=arn, ClientID=client_id)

    got2 = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    assert client_id not in got2["ClientIDList"], "client ID was not removed"
    assert sibling_id in got2["ClientIDList"], "unrelated client ID must survive the removal"

    # Error boundary: the provider ARN does not exist.
    bogus_arn = arn.rsplit("/", 1)[0] + "/does-not-exist.example.org"
    code, message = _error_code(
        lambda: iam.remove_client_id_from_open_id_connect_provider(
            OpenIDConnectProviderArn=bogus_arn, ClientID=client_id
        )
    )
    # Real IAM's wire error code for this shape has no "Exception" suffix.
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"OpenIDConnect Provider not found for arn {bogus_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The failed call against a different ARN must not perturb the real provider.
    got3 = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    assert client_id not in got3["ClientIDList"], (
        f"removed client ID reappeared after an unrelated call failed against a bogus ARN: {got3['ClientIDList']}"
    )


def _error_code(fn):
    """Call fn(); return its (error code, error message). An unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _create_provider(ctx, iam, url, client_ids):
    try:
        resp = iam.create_open_id_connect_provider(
            Url=url,
            ClientIDList=client_ids,
            Tags=[{"Key": "sim2real", "Value": CHECK}],
        )
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "OpenIdIdpCommunicationErrorException":
            raise AssertionError(f"IAM could not reach {url} to verify the OIDC provider") from exc
        raise
    arn = resp["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn))
    return arn


def _user_pool_issuer(ctx) -> str:
    """The issuer URL of a Cognito user pool this check owns, so no third-party IdP is contacted."""
    idp = ctx.client("cognito-idp")
    pool_id = idp.create_user_pool(PoolName=ctx.unique_name("sim2real-behav-userpool-"))["UserPool"]["Id"]
    ctx.on_cleanup(lambda: idp.delete_user_pool(UserPoolId=pool_id))
    return f"https://cognito-idp.{ctx.region}.amazonaws.com/{pool_id}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
