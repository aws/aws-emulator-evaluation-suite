"""update-key-group-duplicate-name-fails."""
from __future__ import annotations

import subprocess

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "update-key-group-duplicate-name-fails"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateKeyGroup renaming a group to a name already used by another key group is
    rejected with KeyGroupAlreadyExists and its exact message, leaves the group's name and
    ETag untouched, and a rename to a fresh, unused name still succeeds."""
    cf = ctx.client("cloudfront")
    pem = _generate_rsa_public_key_pem()

    pk = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-pk-"),
            "Name": ctx.unique_name("sim2real-pk-"),
            "EncodedKey": pem,
            "Comment": "sim2real behavioral check",
        }
    )["PublicKey"]
    pk_id = pk["Id"]
    ctx.on_cleanup(lambda: _delete_public_key(ctx, pk_id))

    name_a = ctx.unique_name("sim2real-kg-")
    group_a = cf.create_key_group(KeyGroupConfig={"Name": name_a, "Items": [pk_id]})["KeyGroup"]
    ctx.on_cleanup(lambda: _delete_key_group(ctx, group_a["Id"]))

    name_b = ctx.unique_name("sim2real-kg-")
    group_b = cf.create_key_group(KeyGroupConfig={"Name": name_b, "Items": [pk_id]})["KeyGroup"]
    group_b_id = group_b["Id"]
    ctx.on_cleanup(lambda: _delete_key_group(ctx, group_b_id))

    etag_b = cf.get_key_group(Id=group_b_id)["ETag"]
    code, message = _error(
        lambda: cf.update_key_group(
            Id=group_b_id, IfMatch=etag_b, KeyGroupConfig={"Name": name_a, "Items": [pk_id]}
        )
    )
    assert code == "KeyGroupAlreadyExists", f"expected KeyGroupAlreadyExists, got {code}"
    expected_message = "Another key group with the same name already exists within the aws account."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # effect absent: group B's name AND version are untouched by the rejected update
    after_reject = cf.get_key_group(Id=group_b_id)
    still = after_reject["KeyGroup"]
    assert still["KeyGroupConfig"]["Name"] == name_b, (
        f"expected rejected update to leave name at {name_b!r}, got {still['KeyGroupConfig']['Name']!r}"
    )
    assert after_reject["ETag"] == etag_b, (
        f"expected ETag to stay at {etag_b!r} after a rejected update, got {after_reject['ETag']!r}"
    )

    # positive control: renaming to a fresh, unused name succeeds
    name_c = ctx.unique_name("sim2real-kg-")
    etag_b2 = cf.get_key_group(Id=group_b_id)["ETag"]
    cf.update_key_group(
        Id=group_b_id, IfMatch=etag_b2, KeyGroupConfig={"Name": name_c, "Items": [pk_id]}
    )
    renamed = cf.get_key_group(Id=group_b_id)["KeyGroup"]
    assert renamed["KeyGroupConfig"]["Name"] == name_c, (
        f"expected positive-control rename to {name_c!r} to succeed, got {renamed['KeyGroupConfig']['Name']!r}"
    )


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _generate_rsa_public_key_pem():
    """Generate a throwaway 2048-bit RSA public key PEM via the openssl CLI."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    priv = subprocess.run(
        ["openssl", "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048"],
        capture_output=True,
        check=True,
    ).stdout
    pub = subprocess.run(
        ["openssl", "pkey", "-pubout"], input=priv, capture_output=True, check=True
    ).stdout
    return pub.decode("ascii")


def _delete_key_group(ctx, group_id):
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_key_group(Id=group_id)["ETag"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchResource":
            return
        raise
    try:
        cf.delete_key_group(Id=group_id, IfMatch=etag)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchResource":
            raise


def _delete_public_key(ctx, key_id):
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_public_key(Id=key_id)["ETag"]
    except ClientError as err:
        if err.response["Error"]["Code"] == "NoSuchPublicKey":
            return
        raise
    try:
        cf.delete_public_key(Id=key_id, IfMatch=etag)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchPublicKey":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
