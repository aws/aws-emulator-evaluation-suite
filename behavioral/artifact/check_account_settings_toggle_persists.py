"""account-settings-toggle-persists."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-settings-toggle-persists"
GROUP = "state"
SERVICES = ["artifact"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:artifact-account-settings")
def run(ctx) -> None:
    """PutAccountSettings toggles notificationSubscriptionStatus and GetAccountSettings
    reflects each transition (SUBSCRIBED <-> NOT_SUBSCRIBED)."""
    art = ctx.client("artifact")
    try:
        original = art.get_account_settings()["accountSettings"]["notificationSubscriptionStatus"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "ResourceNotFoundException":
            raise AssertionError(
                "account settings resource not yet provisioned for this account; "
                "GetAccountSettings returned ResourceNotFoundException before any toggle could be tested"
            ) from e
        raise

    other = "NOT_SUBSCRIBED" if original == "SUBSCRIBED" else "SUBSCRIBED"
    ctx.on_cleanup(lambda: art.put_account_settings(notificationSubscriptionStatus=original))

    put1 = art.put_account_settings(notificationSubscriptionStatus=other)
    put1_status = put1["accountSettings"]["notificationSubscriptionStatus"]
    assert put1_status == other, f"expected PutAccountSettings to echo {other}, got {put1_status}"
    got1 = art.get_account_settings()["accountSettings"]["notificationSubscriptionStatus"]
    assert got1 == other, f"expected {other} after toggle, GetAccountSettings returned {got1}"

    put2 = art.put_account_settings(notificationSubscriptionStatus=original)
    put2_status = put2["accountSettings"]["notificationSubscriptionStatus"]
    assert put2_status == original, f"expected PutAccountSettings to echo {original}, got {put2_status}"
    got2 = art.get_account_settings()["accountSettings"]["notificationSubscriptionStatus"]
    assert got2 == original, f"expected {original} after toggling back, GetAccountSettings returned {got2}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
