"""provisioning-profile-concurrent-create-idempotent-client-token."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "provisioning-profile-concurrent-create-idempotent-client-token"
GROUP = "concurrency"
SERVICES = ["iot-managed-integrations"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Concurrent CreateProvisioningProfile calls sharing Name and ClientToken create exactly one
    profile: every racer that succeeds returns its Id, a racer that loses gets ConflictException with
    the exact name-taken or in-progress message, and a later sequential retry returns that Id."""
    iot = _iot_client(ctx)
    _ensure_custom_endpoint(iot)
    name = ctx.unique_name("sim2real-provprof-race-")  # Name must be <= 36 chars
    client_token = ctx.unique_name("sim2real-token-").replace("-", "")

    def _create():
        try:
            return ("ok", iot.create_provisioning_profile(
                ProvisioningType="FLEET_PROVISIONING",
                Name=name,
                ClientToken=client_token,
                Tags={"sim2real:managed": "true"},
            )["Id"])
        except ClientError as e:
            return ("err", (e.response["Error"]["Code"], e.response["Error"].get("Message")))

    racer_count = 5
    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(lambda _: _create(), range(racer_count)))

    assert len(results) == racer_count, f"expected {racer_count} results, got {len(results)}"
    winners = [r[1] for r in results if r[0] == "ok"]
    losers = [r[1] for r in results if r[0] == "err"]
    # Every successful racer must name one and the same profile.
    assert winners and len(set(winners)) == 1, f"expected one winning Id, got {results}"
    # Overlapping racers may lose with ConflictException; serialized racers all get the Id.
    allowed = {
        ("ConflictException", "A Provisioning Profile with this name already exists."),
        ("ConflictException", "Transaction is ongoing for the provisioning profile."),
    }
    assert all(loser in allowed for loser in losers), f"expected any losing racer refused with {allowed}, got {losers}"
    profile_id = winners[0]
    ctx.on_cleanup(lambda: _delete_profile_ignore_missing(iot, profile_id))

    matching = [
        p for p in iot.list_provisioning_profiles().get("Items", []) if p.get("Name") == name
    ]
    assert len(matching) == 1, f"expected exactly one profile named {name!r}, found {matching}"

    # A sequential retry of the identical (Name, ClientToken) call returns the same Id.
    retry_id = iot.create_provisioning_profile(
        ProvisioningType="FLEET_PROVISIONING",
        Name=name,
        ClientToken=client_token,
        Tags={"sim2real:managed": "true"},
    )["Id"]
    assert retry_id == profile_id, f"expected retry to be remembered as {profile_id}, got {retry_id}"

    iot.delete_provisioning_profile(Identifier=profile_id)
    try:
        iot.get_provisioning_profile(Identifier=profile_id)
        raise AssertionError(f"expected ResourceNotFoundException reading deleted profile {profile_id}")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        assert e.response["Error"].get("Message") == 'Provisioning Profile resource not found', e.response["Error"]
    try:
        iot.delete_provisioning_profile(Identifier=profile_id)
        raise AssertionError(f"expected ResourceNotFoundException re-deleting profile {profile_id}")
    except ClientError as e:
        code = e.response["Error"]["Code"]
        assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
        assert e.response["Error"].get("Message") == 'Provisioning Profile resource not found', e.response["Error"]


def _iot_client(ctx):
    # iot-managed-integrations is only available in ca-central-1 / eu-west-1, so pin the region
    # via ctx.client's `region=` override, which keeps ctx's credentials and endpoint wiring.
    from botocore.config import Config

    return ctx.client(
        "iot-managed-integrations",
        region="eu-west-1",
        config=Config(retries={"max_attempts": 8, "mode": "standard"}),
    )
def _ensure_custom_endpoint(iot) -> None:
    # CreateProvisioningProfile requires the account's per-account custom endpoint to
    # already be registered; create-or-adopt since it is an account-global singleton.
    try:
        iot.register_custom_endpoint()
    except ClientError as e:
        if e.response["Error"]["Code"] != "ConflictException":
            raise


def _delete_profile_ignore_missing(iot, profile_id: str) -> None:
    try:
        iot.delete_provisioning_profile(Identifier=profile_id)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
