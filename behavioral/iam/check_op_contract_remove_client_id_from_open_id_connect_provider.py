"""op-contract-remove-client-id-from-open-id-connect-provider."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "op-contract-remove-client-id-from-open-id-connect-provider"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveClientIDFromOpenIDConnectProvider removes exactly the named client ID from
    the provider's ClientIDList, leaving the rest intact; calling it against a
    nonexistent provider ARN raises NoSuchEntity."""
    iam = ctx.client("iam")
    unique = ctx.unique_name("sim2real-behav-oidc").replace("_", "-")
    url = f"https://{unique}.example.com"
    thumbprint = "0" * 40

    created = iam.create_open_id_connect_provider(
        Url=url,
        ClientIDList=["client-alpha", "client-beta"],
        ThumbprintList=[thumbprint],
        Tags=[{"Key": "sim2real", "Value": "op-contract-remove-client-id-from-open-id-connect-provider"}],
    )
    provider_arn = created["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn))

    before = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    assert set(before["ClientIDList"]) == {"client-alpha", "client-beta"}, (
        f"expected {{'client-alpha', 'client-beta'}}, got {before['ClientIDList']!r}"
    )

    iam.remove_client_id_from_open_id_connect_provider(
        OpenIDConnectProviderArn=provider_arn, ClientID="client-alpha"
    )

    after = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    assert after["ClientIDList"] == ["client-beta"], (
        f"expected ['client-beta'], got {after['ClientIDList']!r}"
    )

    # error boundary: provider ARN does not exist
    fake_arn = provider_arn[:-4] + "aaaa"
    code, message = _error(lambda: iam.remove_client_id_from_open_id_connect_provider(
        OpenIDConnectProviderArn=fake_arn, ClientID="client-beta"
    ))
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code}"
    expected = f"OpenIDConnect Provider not found for arn {fake_arn}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    # confirm the real provider was untouched by the failed call against the fake arn
    still_there = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    assert still_there["ClientIDList"] == ["client-beta"], (
        f"expected ['client-beta'], got {still_there['ClientIDList']!r}"
    )


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
