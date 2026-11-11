"""import-playback-key-pair-duplicate-conflict-rejected."""
from __future__ import annotations

import subprocess

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "import-playback-key-pair-duplicate-conflict-rejected"
GROUP = "overly-permissive"
SERVICES = ["ivs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Importing the same playback key material twice fails ConflictException with the exact message and adds no
    key pair; after the first is deleted, the same material imports again under a new ARN."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    pem = _generate_ec_public_key_pem()
    ivs = ctx.client("ivs")

    first_arn = ivs.import_playback_key_pair(
        publicKeyMaterial=pem, name=ctx.unique_name("sim2real-ivs-dupkp-a-")
    )["keyPair"]["arn"]
    ctx.on_cleanup(lambda: _delete_key_pair_if_present(ivs, first_arn))

    dup_name = ctx.unique_name("sim2real-ivs-dupkp-b-")
    error = _error(
        lambda: ivs.import_playback_key_pair(publicKeyMaterial=pem, name=dup_name)
    )
    assert error["Code"] == "ConflictException", f"expected ConflictException, got {error['Code']!r}"
    assert error["Message"] == (
        "A playback-key resource already exists with the given publicKeyMaterial"
    ), repr(error["Message"])

    assert dup_name not in _key_pair_names(ivs), (
        f"a duplicate key pair {dup_name!r} was created despite the error"
    )

    got = ivs.get_playback_key_pair(arn=first_arn)["keyPair"]
    assert got["arn"] == first_arn, f"expected {first_arn!r}, got {got['arn']!r}"

    # Restore leg: delete the first key pair, prove it is gone via an independent
    # read, then reimport the identical material and demand it now succeeds -- the
    # conflict was scoped to the existing resource, not the material.
    ivs.delete_playback_key_pair(arn=first_arn)

    get_error = _error(lambda: ivs.get_playback_key_pair(arn=first_arn))
    assert get_error["Code"] == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading deleted {first_arn}, got {get_error['Code']!r}"
    )
    assert get_error["Message"] == f"Resource: {first_arn} not found", repr(get_error["Message"])

    second_arn = ivs.import_playback_key_pair(
        publicKeyMaterial=pem, name=ctx.unique_name("sim2real-ivs-dupkp-c-")
    )["keyPair"]["arn"]
    ctx.on_cleanup(lambda: _delete_key_pair_if_present(ivs, second_arn))
    assert second_arn != first_arn, "reimport after delete reused the deleted arn"

    reread = ivs.get_playback_key_pair(arn=second_arn)["keyPair"]
    assert reread["arn"] == second_arn, f"expected {second_arn!r}, got {reread['arn']!r}"


def _key_pair_names(ivs) -> set[str]:
    """Every playback key pair name in the account, read across all pages."""
    return {
        kp.get("name")
        for page in ivs.get_paginator("list_playback_key_pairs").paginate()
        for kp in page.get("keyPairs", [])
    }


def _error(fn):
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]
    raise AssertionError(f"expected a ClientError but the call succeeded with {result!r}")


def _delete_key_pair_if_present(ivs, arn: str) -> None:
    try:
        ivs.delete_playback_key_pair(arn=arn)
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
