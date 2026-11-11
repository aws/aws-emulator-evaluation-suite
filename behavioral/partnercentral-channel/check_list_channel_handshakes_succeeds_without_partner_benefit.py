"""list-channel-handshakes-succeeds-without-partner-benefit."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-channel-handshakes-succeeds-without-partner-benefit"
GROUP = "data-plane"
SERVICES = ["partnercentral-channel"]

CATALOG = "Sandbox"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListChannelHandshakes is not entitlement-gated: for a caller without an active AWS Partner
    benefit it returns an empty items list for both participantType values and for a filter on a
    nonexistent associatedResourceIdentifier."""
    client = ctx.client("partnercentral-channel")

    for participant_type in ("SENDER", "RECEIVER"):
        resp = client.list_channel_handshakes(
            handshakeType="PROGRAM_MANAGEMENT_ACCOUNT",
            catalog=CATALOG,
            participantType=participant_type,
            maxResults=10,
        )
        items = resp["items"]
        assert isinstance(items, list), (
            f"items should be a list for participantType={participant_type}, "
            f"got {type(items)!r}"
        )
        assert items == [], (
            f"account holds no PROGRAM_MANAGEMENT_ACCOUNT handshake as "
            f"{participant_type}, expected [], got {items!r}"
        )

    fake_pma_id = "pma-1111111111111"

    filtered = client.list_channel_handshakes(
        handshakeType="PROGRAM_MANAGEMENT_ACCOUNT",
        catalog=CATALOG,
        participantType="SENDER",
        associatedResourceIdentifiers=[fake_pma_id],
        maxResults=10,
    )
    assert filtered["items"] == [], (
        "filtering by a nonexistent associatedResourceIdentifier should return no "
        f"items, got {filtered['items']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
