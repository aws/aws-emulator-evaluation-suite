"""e2e-oidc-client-id-federation-workflow."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "e2e-oidc-client-id-federation-workflow"
GROUP = "e2e"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A full OIDC provider lifecycle -- create, add a client ID, rotate the
    thumbprint, remove a client ID, delete -- leaves each subsequent read
    reflecting exactly the prior step's consequence."""
    iam = ctx.client("iam")
    host = ctx.unique_name("sim2real-behav-oidc-").lower()
    url = f"https://{host}.example.com"
    thumbprint_a = "a" * 40
    thumbprint_b = "b" * 40

    provider_arn = iam.create_open_id_connect_provider(
        Url=url,
        ClientIDList=["app-one"],
        ThumbprintList=[thumbprint_a],
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["OpenIDConnectProviderArn"]
    ctx.on_cleanup(
        lambda: _safe(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn))
    )

    # Step 1: created with one client ID and one thumbprint.
    step1 = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    assert step1["Url"] == f"{host}.example.com", (
        f"expected stored Url {host}.example.com, got {step1['Url']!r}"
    )
    assert step1["ClientIDList"] == ["app-one"], (
        f"expected ClientIDList ['app-one'] on create, got {step1['ClientIDList']!r}"
    )
    assert step1["ThumbprintList"] == [thumbprint_a], (
        f"expected ThumbprintList [{thumbprint_a!r}] on create, got {step1['ThumbprintList']!r}"
    )

    # Step 2: adding a client ID appends it to the list.
    iam.add_client_id_to_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn, ClientID="app-two")
    step2 = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    assert sorted(step2["ClientIDList"]) == ["app-one", "app-two"], (
        f"expected AddClientID to grow the list to ['app-one', 'app-two'], got {step2['ClientIDList']!r}"
    )

    # Step 3: rotating the thumbprint fully replaces the list, not appends.
    iam.update_open_id_connect_provider_thumbprint(
        OpenIDConnectProviderArn=provider_arn, ThumbprintList=[thumbprint_b]
    )
    step3 = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    assert step3["ThumbprintList"] == [thumbprint_b], (
        f"expected UpdateThumbprint to REPLACE the list with [{thumbprint_b!r}], "
        f"got {step3['ThumbprintList']!r}"
    )

    # Step 4: removing a client ID leaves only the other one.
    iam.remove_client_id_from_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn, ClientID="app-one")
    step4 = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    assert step4["ClientIDList"] == ["app-two"], (
        f"expected RemoveClientID to leave only ['app-two'], got {step4['ClientIDList']!r}"
    )

    # Step 5: deletion makes the provider unreachable.
    iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn)
    code, message = _error(lambda: iam.get_open_id_connect_provider(OpenIDConnectProviderArn=provider_arn))
    assert code == "NoSuchEntity", f"expected NoSuchEntity reading a deleted OIDC provider, got {code!r}"
    expected_message = f"OpenIDConnect Provider not found for arn {provider_arn}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected this call to fail, but it SUCCEEDED and returned {result!r}")


def _safe(fn):
    try:
        fn()
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
