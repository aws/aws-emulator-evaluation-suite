"""concurrent-create-configuration-set-same-name-one-winner."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "concurrent-create-configuration-set-same-name-one-winner"
GROUP = "overly-permissive"
SERVICES = ["pinpoint-sms-voice-v2"]


def _teardown(undo, *not_found: str):
    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


@tags(
    "axis:rejection",
    "cap:c1",
    "concern:negative-classes",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Two concurrent CreateConfigurationSet calls for the same name leave exactly one
    winner and one ConflictException loser, under every interleaving including serial.
    """
    client = ctx.client("pinpoint-sms-voice-v2")
    name = ctx.unique_name("sim2real-behav-cfgset-")
    ctx.on_cleanup(
        _teardown(
            lambda: client.delete_configuration_set(ConfigurationSetName=name),
            "ResourceNotFoundException",
        )
    )

    def attempt():
        try:
            client.create_configuration_set(ConfigurationSetName=name)
            return ("ok", None)
        except ClientError as exc:
            return ("error", exc.response["Error"]["Code"], exc.response["Error"].get("Message"))

    with ThreadPoolExecutor(max_workers=2) as pool:
        results = list(pool.map(lambda _: attempt(), range(2)))

    winners = [r for r in results if r[0] == "ok"]
    losers = [r for r in results if r[0] == "error"]
    assert len(winners) == 1, f"expected exactly one winner, got {len(winners)}: {results!r}"
    assert len(losers) == 1, f"expected exactly one loser, got {len(losers)}: {results!r}"

    loser_code, loser_message = losers[0][1], losers[0][2]
    assert loser_code == "ConflictException", f"loser carried {loser_code!r}, not ConflictException"
    expected_message = (
        f'Conflict Occurred - Reason="RESOURCE_ALREADY_EXISTS" '
        f'ResourceType="configuration-set" ResourceId="{name}"'
    )
    assert loser_message == expected_message, (
        f"loser message {loser_message!r} did not match {expected_message!r}"
    )

    described = client.describe_configuration_sets(ConfigurationSetNames=[name])
    sets = described["ConfigurationSets"]
    assert len(sets) == 1, f"expected exactly one configuration set named {name!r}, got {sets!r}"
    assert sets[0]["ConfigurationSetName"] == name, (
        f"unexpected name {sets[0]['ConfigurationSetName']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
