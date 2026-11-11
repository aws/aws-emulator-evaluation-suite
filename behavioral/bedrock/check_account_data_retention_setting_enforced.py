"""account-data-retention-setting-enforced."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "account-data-retention-setting-enforced"
GROUP = "server-side"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:bedrock-account-data-retention")
def run(ctx) -> None:
    """PutAccountDataRetention returns the requested mode and a separate GetAccountDataRetention
    reflects it, and after a second change to another mode GetAccountDataRetention reflects the
    latest write.
    """
    bedrock = ctx.client("bedrock")

    original = bedrock.get_account_data_retention()
    original_mode = original["mode"]
    ctx.on_cleanup(lambda: bedrock.put_account_data_retention(mode=original_mode))

    target_mode = "none" if original_mode != "none" else "default"

    put_resp = bedrock.put_account_data_retention(mode=target_mode)
    assert put_resp["mode"] == target_mode, (
        f"expected PutAccountDataRetention to echo the requested mode={target_mode!r}, "
        f"got {put_resp['mode']!r}"
    )

    fetched = bedrock.get_account_data_retention()
    assert fetched["mode"] == target_mode, (
        f"expected an independent GetAccountDataRetention to reflect the just-set "
        f"mode={target_mode!r}, got {fetched['mode']!r}"
    )

    # Flip it again to prove the server state actually tracks the latest write,
    # not just the first one.
    second_mode = "default" if target_mode != "default" else "none"
    bedrock.put_account_data_retention(mode=second_mode)
    fetched_again = bedrock.get_account_data_retention()
    assert fetched_again["mode"] == second_mode, (
        f"expected the second write to mode={second_mode!r} to be reflected on the next "
        f"independent read, got {fetched_again['mode']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
