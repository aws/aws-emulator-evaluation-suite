"""import-playback-key-pair-round-trip."""
from __future__ import annotations

import os
import re
import subprocess
import tempfile

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "import-playback-key-pair-round-trip"
GROUP = "state"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ImportPlaybackKeyPair returns a colon-hex fingerprint that Get and List agree on; after delete the key leaves
    the list, and Get and a second delete fail ResourceNotFoundException with the exact message."""
    pem = _generate_ecdsa_p384_public_key_pem()
    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-key-")
    resp = ivs.import_playback_key_pair(
        name=name, publicKeyMaterial=pem, tags={"sim2real": CHECK}
    )
    arn = resp["keyPair"]["arn"]
    ctx.on_cleanup(lambda: _delete_key_pair_if_present(ivs, arn))

    assert resp["keyPair"]["name"] == name, (
        f"expected imported name {name!r}, got {resp['keyPair']['name']!r}"
    )
    fingerprint = resp["keyPair"]["fingerprint"]
    assert re.fullmatch(r"([0-9A-Fa-f]{2}:)+[0-9A-Fa-f]{2}", fingerprint), (
        f"expected a hex-colon fingerprint, got {fingerprint!r}"
    )
    num_groups = fingerprint.count(":") + 1
    # A hex-colon fingerprint's group count is a hash digest's byte length. Accept any
    # standard digest size rather than assuming a specific algorithm the docs don't pin down.
    assert num_groups in (16, 20, 28, 32, 48, 64), f"unexpected fingerprint length: {fingerprint}"

    got = ivs.get_playback_key_pair(arn=arn)["keyPair"]
    assert got["arn"] == arn, f"expected arn {arn!r}, got {got['arn']!r}"
    assert got["fingerprint"] == fingerprint, (
        f"expected Get to echo Import's fingerprint {fingerprint!r}, got {got['fingerprint']!r}"
    )

    listed = ivs.list_playback_key_pairs()["keyPairs"]
    assert any(k["arn"] == arn for k in listed), f"expected {arn!r} in ListPlaybackKeyPairs"

    ivs.delete_playback_key_pair(arn=arn)

    error = _error(lambda: ivs.get_playback_key_pair(arn=arn))
    assert error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException, got {error['Code']!r}"
    )
    assert error["Message"] == f"Resource: {arn} not found", repr(error["Message"])

    listed_after = ivs.list_playback_key_pairs()["keyPairs"]
    assert not any(k["arn"] == arn for k in listed_after), (
        f"expected {arn!r} to be gone from ListPlaybackKeyPairs after delete"
    )

    # Mutation on the dead id: a second delete of the same key must not resurrect it.
    second = _error(lambda: ivs.delete_playback_key_pair(arn=arn))
    assert second["Code"] == "ResourceNotFoundException", (
        f"expected a double-delete of the same key to also 404, got {second['Code']!r}"
    )
    assert second["Message"] == f"Resource: {arn} not found", repr(second["Message"])


def _delete_key_pair_if_present(ivs, arn):
    from botocore.exceptions import ClientError

    try:
        ivs.delete_playback_key_pair(arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _generate_ecdsa_p384_public_key_pem() -> str:
    import shutil

    require_tools("openssl")
    openssl = shutil.which("openssl")
    with tempfile.TemporaryDirectory() as d:
        priv = os.path.join(d, "priv.pem")
        pub = os.path.join(d, "pub.pem")
        subprocess.run(
            [openssl, "ecparam", "-genkey", "-name", "secp384r1", "-noout", "-out", priv],
            check=True, capture_output=True,
        )
        subprocess.run(
            [openssl, "ec", "-in", priv, "-pubout", "-out", pub],
            check=True, capture_output=True,
        )
        with open(pub) as f:
            return f.read()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
