"""concurrent-keypair-creation-duplicate-name-race."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags

CHECK = "concurrent-keypair-creation-duplicate-name-race"
GROUP = "concurrency"
SERVICES = ["lightsail"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Racing CreateKeyPair calls for the same name: exactly one succeeds, the rest fail with InvalidInputException."""
    ls = ctx.client("lightsail")
    name = ctx.unique_name("sim2real-ls-kprace-")
    racer_count = 6

    def _create():
        try:
            ls.create_key_pair(keyPairName=name, tags=[{"key": "sim2real", "value": CHECK}])
            return ("ok", None)
        except Exception as exc:  # noqa: BLE001 - classify via botocore below
            return ("error", _error_code(exc))

    with ThreadPoolExecutor(max_workers=racer_count) as pool:
        results = list(pool.map(lambda _: _create(), range(racer_count)))

    ctx.on_cleanup(lambda: ls.delete_key_pair(keyPairName=name))

    successes = [r for r in results if r[0] == "ok"]
    failures = [r for r in results if r[0] == "error"]
    assert len(successes) == 1, f"expected exactly 1 winner among {racer_count} racers, got {len(successes)}: {results}"
    assert len(failures) == racer_count - 1
    for _, code in failures:
        assert code == ("InvalidInputException", f"Some names are already in use: {name}"), (
            f"unexpected loser error: {code!r}"
        )

    # The name uniqueness constraint held: only one key pair with this name exists.
    key_pair = ls.get_key_pair(keyPairName=name)["keyPair"]
    assert key_pair["name"] == name

    # Positive control: a genuinely different name is unaffected by the race and succeeds,
    # proving the losers above were rejected for colliding on `name` -- not because CreateKeyPair
    # rejects concurrent callers, or any create, outright.
    control_name = ctx.unique_name("sim2real-ls-kprace-ctl-")
    control = ls.create_key_pair(
        keyPairName=control_name, tags=[{"key": "sim2real", "value": CHECK}]
    )["keyPair"]
    ctx.on_cleanup(lambda: ls.delete_key_pair(keyPairName=control_name))
    assert control["name"] == control_name


def _error_code(exc):
    from botocore.exceptions import ClientError

    if isinstance(exc, ClientError):
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    return None


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
