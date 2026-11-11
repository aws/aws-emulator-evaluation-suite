"""import-playback-key-pair-fingerprint-consistency."""
from __future__ import annotations

import subprocess
import tempfile

from behavioral_harness import tags

CHECK = "import-playback-key-pair-fingerprint-consistency"
GROUP = "data-plane"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Each imported ECDSA P-384 public key gets a distinct, stable fingerprint computed
    from the key material."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    ivs = ctx.client("ivs")
    pem_a = _generate_ecdsa_p384_public_key_pem()
    pem_b = _generate_ecdsa_p384_public_key_pem()
    assert pem_a != pem_b

    imported_a = ivs.import_playback_key_pair(
        publicKeyMaterial=pem_a,
        name=ctx.unique_name("sim2real-ivs-kp-a-"),
        tags={"purpose": "sim2real"},
    )["keyPair"]
    ctx.on_cleanup(lambda: ivs.delete_playback_key_pair(arn=imported_a["arn"]))
    imported_b = ivs.import_playback_key_pair(
        publicKeyMaterial=pem_b,
        name=ctx.unique_name("sim2real-ivs-kp-b-"),
        tags={"purpose": "sim2real"},
    )["keyPair"]
    ctx.on_cleanup(lambda: ivs.delete_playback_key_pair(arn=imported_b["arn"]))

    assert imported_a["fingerprint"]
    assert imported_b["fingerprint"]
    # Two distinct key pairs must never collide on the fingerprint used to identify them.
    assert imported_a["fingerprint"] != imported_b["fingerprint"]

    # The fingerprint returned by Get must be stable and match what Import originally returned.
    refetched_a = ivs.get_playback_key_pair(arn=imported_a["arn"])["keyPair"]
    assert refetched_a["fingerprint"] == imported_a["fingerprint"]


def _generate_ecdsa_p384_public_key_pem() -> str:
    # IVS playback keys must be ECDSA P-384 (secp384r1); see
    # https://docs.aws.amazon.com/ivs/latest/LowLatencyUserGuide/private-channels-create-key.html
    with tempfile.TemporaryDirectory() as tmp:
        private_path = f"{tmp}/priv.pem"
        public_path = f"{tmp}/pub.pem"
        subprocess.run(
            ["openssl", "ecparam", "-name", "secp384r1", "-genkey", "-noout", "-out", private_path],
            check=True,
            capture_output=True,
        )
        subprocess.run(
            ["openssl", "ec", "-in", private_path, "-pubout", "-out", public_path],
            check=True,
            capture_output=True,
        )
        with open(public_path) as fh:
            return fh.read()


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
