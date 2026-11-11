"""list-playback-key-pairs-reflects-imported."""
from __future__ import annotations

import subprocess
import tempfile

from behavioral_harness import tags

CHECK = "list-playback-key-pairs-reflects-imported"
GROUP = "data-plane"
SERVICES = ["ivs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPlaybackKeyPairs surfaces a freshly imported key pair by ARN and name (summary form,
    with no key material), and DeletePlaybackKeyPair is terminal: an independent list, a
    GetPlaybackKeyPair and a second delete on the same arn all confirm the key pair is gone."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    ivs = ctx.client("ivs")
    name = ctx.unique_name("sim2real-ivs-lspkp-")
    pem = _generate_ecdsa_p384_public_key_pem()
    imported = ivs.import_playback_key_pair(
        publicKeyMaterial=pem, name=name, tags={"purpose": "sim2real"}
    )["keyPair"]
    arn = imported["arn"]
    ctx.on_cleanup(lambda: _delete_key_pair_if_present(ivs, arn))

    summaries = ivs.list_playback_key_pairs()["keyPairs"]
    matches = [s for s in summaries if s["arn"] == arn]
    assert len(matches) == 1, (
        f"expected exactly one ListPlaybackKeyPairs summary for {arn}, got {len(matches)}"
    )
    assert matches[0]["name"] == name, (
        f"expected summary name {name!r}, got {matches[0]['name']!r}"
    )

    ivs.delete_playback_key_pair(arn=arn)

    after_delete = ivs.list_playback_key_pairs()["keyPairs"]
    assert arn not in {s["arn"] for s in after_delete}, (
        f"deleted key pair {arn} still present in ListPlaybackKeyPairs"
    )

    get_error = _error(lambda: ivs.get_playback_key_pair(arn=arn))
    assert get_error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException from GetPlaybackKeyPair on deleted {arn}, got {get_error['Code']!r}"
    )
    assert get_error["Message"] == f"Resource: {arn} not found", repr(get_error["Message"])

    redelete_error = _error(lambda: ivs.delete_playback_key_pair(arn=arn))
    assert redelete_error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException re-deleting {arn}, got {redelete_error['Code']!r}"
    )
    assert redelete_error["Message"] == f"Resource: {arn} not found", repr(redelete_error["Message"])


def _error(fn):
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _delete_key_pair_if_present(ivs, arn: str) -> None:
    from botocore.exceptions import ClientError

    try:
        ivs.delete_playback_key_pair(arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
