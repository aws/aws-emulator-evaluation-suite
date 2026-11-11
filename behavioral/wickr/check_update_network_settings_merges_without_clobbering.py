"""update-network-settings-merges-without-clobbering."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-network-settings-merges-without-clobbering"
GROUP = "network-settings"
SERVICES = ["wickr"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()`` where a failed delete raises, except on ``not_found`` codes."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _settings(wickr, network_id: str) -> dict:
    return {
        s["optionName"]: s["value"]
        for s in wickr.get_network_settings(networkId=network_id)["settings"]
    }


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateNetworkSettings merges one changed setting into the existing set rather than
    replacing it, so an earlier, unrelated change survives a later, independent one.

    Reference: https://docs.aws.amazon.com/wickr/latest/APIReference/API_UpdateNetworkSettings.html
    """
    wickr = ctx.client("wickr", region="us-east-1")
    network_name = ctx.unique_name("sim2real")[:20]

    network = wickr.create_network(networkName=network_name, accessLevel="STANDARD")
    network_id = network["networkId"]
    ctx.on_cleanup(_teardown(lambda: wickr.delete_network(networkId=network_id), "ForbiddenError"))

    before = _settings(wickr, network_id)
    assert before["enableClientMetrics"] == "true", (
        f"expected enableClientMetrics to default true, got {before['enableClientMetrics']!r}"
    )
    assert "enableTrustedDataFormat" not in before, (
        f"expected enableTrustedDataFormat absent before it is ever set, got {before!r}"
    )

    wickr.update_network_settings(networkId=network_id, settings={"enableClientMetrics": False})
    after_first = _settings(wickr, network_id)
    assert after_first["enableClientMetrics"] == "false", (
        f"expected enableClientMetrics false after the update, got {after_first['enableClientMetrics']!r}"
    )

    wickr.update_network_settings(networkId=network_id, settings={"enableTrustedDataFormat": True})
    after_second = _settings(wickr, network_id)
    assert after_second["enableTrustedDataFormat"] == "true", (
        f"expected enableTrustedDataFormat true after its own update, "
        f"got {after_second['enableTrustedDataFormat']!r}"
    )
    assert after_second["enableClientMetrics"] == "false", (
        "the independent enableTrustedDataFormat update reset enableClientMetrics to "
        f"{after_second['enableClientMetrics']!r}; a settings update must merge, not replace"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
