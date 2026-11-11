"""account-preferences-update-get-roundtrip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "account-preferences-update-get-roundtrip"
GROUP = "state"
SERVICES = ["chatbot"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:chatbot-account-preferences")
def run(ctx) -> None:
    """UpdateAccountPreferences flips UserAuthorizationRequired in its response and in GetAccountPreferences;
    TrainingDataCollectionEnabled, set in the same call, is bool-typed when the update returns it and always
    returned bool-typed by the read (its value is not asserted, as an organization opt-out policy can override it)."""
    chatbot = ctx.client("chatbot")

    original = chatbot.get_account_preferences()["AccountPreferences"]
    original_auth = original.get("UserAuthorizationRequired", False)
    original_training = original.get("TrainingDataCollectionEnabled", False)
    ctx.on_cleanup(
        lambda: chatbot.update_account_preferences(
            UserAuthorizationRequired=original_auth,
            TrainingDataCollectionEnabled=original_training,
        )
    )

    flipped_auth = not original_auth
    flipped_training = not original_training
    updated = chatbot.update_account_preferences(
        UserAuthorizationRequired=flipped_auth,
        TrainingDataCollectionEnabled=flipped_training,
    )["AccountPreferences"]
    assert updated["UserAuthorizationRequired"] == flipped_auth, (
        f"expected UserAuthorizationRequired={flipped_auth!r} after update, "
        f"got {updated['UserAuthorizationRequired']!r}"
    )
    assert isinstance(updated.get("TrainingDataCollectionEnabled", False), bool), (
        "expected TrainingDataCollectionEnabled, when present, to be bool-typed in the "
        f"update response, got {updated.get('TrainingDataCollectionEnabled')!r}"
    )

    fetched = chatbot.get_account_preferences()["AccountPreferences"]
    assert fetched["UserAuthorizationRequired"] == flipped_auth, (
        f"expected UserAuthorizationRequired={flipped_auth!r} on the independent read, "
        f"got {fetched['UserAuthorizationRequired']!r}"
    )
    assert isinstance(fetched["TrainingDataCollectionEnabled"], bool), (
        "expected TrainingDataCollectionEnabled to be present and bool-typed on the "
        f"independent read, got {fetched['TrainingDataCollectionEnabled']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
