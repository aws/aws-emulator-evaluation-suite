"""concurrent-import-playback-key-pair-race."""
from __future__ import annotations

import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "concurrent-import-playback-key-pair-race"
GROUP = "concurrency"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Importing the same public-key material concurrently from N racers must let
    exactly one succeed; the rest get ConflictException (duplicate fingerprint), never
    N distinct key pairs for one key."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    pem = _generate_ec_public_key_pem()
    ivs = ctx.client("ivs")
    n = 5

    def _attempt(i):
        name = ctx.unique_name(f"sim2real-ivs-kp{i}-")
        try:
            arn = ivs.import_playback_key_pair(
                publicKeyMaterial=pem, name=name, tags={"purpose": "sim2real"}
            )["keyPair"]["arn"]
            return ("ok", arn, name, None)
        except ClientError as e:
            return (e.response["Error"]["Code"], None, name, e.response["Error"]["Message"])

    with ThreadPoolExecutor(max_workers=n) as pool:
        futures = [pool.submit(_attempt, i) for i in range(n)]
        results = [f.result() for f in as_completed(futures)]

    successes = [(arn, name) for status, arn, name, _msg in results if status == "ok"]
    failures = [status for status, arn, name, _msg in results if status != "ok"]
    messages = [msg for status, _arn, _name, msg in results if status != "ok"]

    assert len(successes) == 1, f"expected exactly 1 success, got {len(successes)}: {results}"
    assert len(failures) == n - 1, f"expected {n - 1} rejections, got {len(failures)}: {results}"
    assert all(code == "ConflictException" for code in failures), failures
    expected = "A playback-key resource already exists with the given publicKeyMaterial"
    assert all(msg == expected for msg in messages), messages

    winner_arn, winner_name = successes[0]
    ctx.on_cleanup(lambda: ivs.delete_playback_key_pair(arn=winner_arn))
    got = ivs.get_playback_key_pair(arn=winner_arn)["keyPair"]
    assert got["arn"] == winner_arn, f"expected arn {winner_arn!r}, got {got['arn']!r}"
    assert got["name"] == winner_name, (
        f"expected the surviving key pair's name to be the winning racer's "
        f"{winner_name!r}, got {got['name']!r}"
    )


def _generate_ec_public_key_pem():
    priv = subprocess.run(
        ["openssl", "ecparam", "-genkey", "-name", "prime256v1", "-noout"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    pub = subprocess.run(
        ["openssl", "ec", "-pubout"],
        input=priv,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return pub


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
