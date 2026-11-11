"""account-data-retention-put-get-enforced."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "account-data-retention-put-get-enforced"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:bedrock-account-data-retention")
def run(ctx) -> None:
    """PutAccountDataRetention persists a mode that GetAccountDataRetention reflects exactly."""
    bedrock = ctx.client("bedrock")

    original_mode = bedrock.get_account_data_retention()["mode"]

    def _restore() -> None:
        bedrock.put_account_data_retention(mode=original_mode)

    ctx.on_cleanup(_restore)

    # Pick a target mode that differs from whatever is currently set, so the
    # write is observable rather than a no-op.
    target_mode = "none" if original_mode != "none" else "default"

    put_resp = bedrock.put_account_data_retention(mode=target_mode)
    assert put_resp["mode"] == target_mode, (
        f"expected PutAccountDataRetention to echo mode {target_mode!r}, got {put_resp['mode']!r}"
    )

    got = bedrock.get_account_data_retention()
    assert got["mode"] == target_mode, (
        f"expected persisted mode {target_mode!r}, GetAccountDataRetention reported {got['mode']!r}"
    )

    # Flip it again to make sure the setting is not stuck / cached and each
    # write is independently observable.
    second_target = "default" if target_mode != "default" else "inherit"
    bedrock.put_account_data_retention(mode=second_target)
    got2 = bedrock.get_account_data_retention()
    assert got2["mode"] == second_target, (
        f"expected persisted mode {second_target!r}, GetAccountDataRetention reported {got2['mode']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
