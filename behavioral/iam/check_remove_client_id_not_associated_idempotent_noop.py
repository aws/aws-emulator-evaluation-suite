"""remove-client-id-not-associated-idempotent-noop."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "remove-client-id-not-associated-idempotent-noop"
GROUP = "ordering"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """RemoveClientIDFromOpenIDConnectProvider on a ClientID that was never added
    succeeds without error and leaves the existing ClientIDList unchanged."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-oidcrmnoop-")
    url = f"https://{name}.example.com"
    thumbprint = "b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8b8"

    existing_client_id = "sim2real-aud-existing"
    created = iam.create_open_id_connect_provider(
        Url=url,
        ThumbprintList=[thumbprint],
        ClientIDList=[existing_client_id],
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = created["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn))

    before = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)["ClientIDList"]
    assert before == [existing_client_id], (
        f"provider must start with only the seeded client id: got {before!r}"
    )

    # This client id was never associated with the provider.
    never_added_client_id = "sim2real-aud-never-added"
    iam.remove_client_id_from_open_id_connect_provider(
        OpenIDConnectProviderArn=arn, ClientID=never_added_client_id
    )

    after = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)["ClientIDList"]
    assert after == before, (
        f"ClientIDList must be unchanged by a no-op removal: before={before!r} after={after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
