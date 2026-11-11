"""add-client-id-duplicate-idempotent-dedup."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "add-client-id-duplicate-idempotent-dedup"
GROUP = "ordering"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """AddClientIDToOpenIDConnectProvider called twice with the same ClientID is a
    no-op the second time: the ClientIDList contains exactly one entry for it."""
    iam = ctx.client("iam")
    name = ctx.unique_name("sim2real-oidcdedup-")
    url = f"https://{name}.example.com"
    thumbprint = "a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9a9"

    created = iam.create_open_id_connect_provider(Url=url, ThumbprintList=[thumbprint])
    arn = created["OpenIDConnectProviderArn"]
    ctx.on_cleanup(lambda: iam.delete_open_id_connect_provider(OpenIDConnectProviderArn=arn))

    client_id = "sim2real-aud-1"
    iam.add_client_id_to_open_id_connect_provider(
        OpenIDConnectProviderArn=arn, ClientID=client_id
    )
    # Second call with the SAME client id must succeed as a no-op, not duplicate.
    iam.add_client_id_to_open_id_connect_provider(
        OpenIDConnectProviderArn=arn, ClientID=client_id
    )

    got = iam.get_open_id_connect_provider(OpenIDConnectProviderArn=arn)
    client_ids = got["ClientIDList"]
    assert client_ids.count(client_id) == 1, (
        f"expected exactly one occurrence of {client_id!r} in ClientIDList, got {client_ids!r}"
    )
    assert client_ids == [client_id], f"unexpected ClientIDList contents: {client_ids!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
