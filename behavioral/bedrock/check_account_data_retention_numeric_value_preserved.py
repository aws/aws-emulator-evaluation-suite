"""account-data-retention-numeric-value-preserved."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "account-data-retention-numeric-value-preserved"
GROUP = "representation"
SERVICES = ["bedrock"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:bedrock-account-data-retention")
def run(ctx) -> None:
    """Each DataRetentionMode value written via Put is echoed and read back exactly, never coerced.
    The API models an enum `mode`, not a numeric period, so exactness is the enum round trip."""
    bedrock = ctx.client("bedrock")

    original_mode = bedrock.get_account_data_retention()["mode"]
    ctx.on_cleanup(lambda: bedrock.put_account_data_retention(mode=original_mode))

    # Distinct values in sequence, so a value stuck from the previous iteration is caught.
    sequence = ["none", "default", "inherit", "provider_data_share"]
    for mode in sequence:
        put_resp = bedrock.put_account_data_retention(mode=mode)
        assert put_resp["mode"] == mode, (
            f"PutAccountDataRetention echoed {put_resp['mode']!r} instead of the requested {mode!r}"
        )
        got = bedrock.get_account_data_retention()
        assert got["mode"] == mode, (
            f"GetAccountDataRetention returned {got['mode']!r} after setting mode={mode!r} "
            "-- the value was not preserved exactly"
        )
        assert isinstance(got["mode"], str), (
            f"GetAccountDataRetention returned a non-string mode {got['mode']!r} (type "
            f"{type(got['mode']).__name__}) for requested mode={mode!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
