"""account-preferences-update-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "account-preferences-update-roundtrip"
GROUP = "lifecycle"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:chatbot-account-preferences")
def run(ctx) -> None:
    """UpdateAccountPreferences flips UserAuthorizationRequired and the new value is
    visible on the next GetAccountPreferences; the original value is restored afterwards."""
    chatbot = ctx.client("chatbot")
    original = chatbot.get_account_preferences()["AccountPreferences"]
    original_value = original["UserAuthorizationRequired"]
    flipped = not original_value

    ctx.on_cleanup(lambda: chatbot.update_account_preferences(UserAuthorizationRequired=original_value))

    chatbot.update_account_preferences(UserAuthorizationRequired=flipped)
    after = chatbot.get_account_preferences()["AccountPreferences"]
    assert after["UserAuthorizationRequired"] == flipped, (
        f"expected UserAuthorizationRequired={flipped} on independent GetAccountPreferences "
        f"read after flipping it, got {after['UserAuthorizationRequired']}"
    )

    chatbot.update_account_preferences(UserAuthorizationRequired=original_value)
    restored = chatbot.get_account_preferences()["AccountPreferences"]
    assert restored["UserAuthorizationRequired"] == original_value, (
        f"expected UserAuthorizationRequired={original_value} on independent GetAccountPreferences "
        f"read after restoring it, got {restored['UserAuthorizationRequired']}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
