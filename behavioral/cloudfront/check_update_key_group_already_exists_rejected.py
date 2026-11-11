"""update-key-group-already-exists-rejected."""
from __future__ import annotations

import subprocess
import tempfile
from pathlib import Path

from behavioral_harness import tags

CHECK = "update-key-group-already-exists-rejected"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateKeyGroup renaming a key group to another key group's Name fails with KeyGroupAlreadyExists and its exact
    message, leaving its Name and ETag unchanged; renaming it to a free name succeeds."""
    cf = ctx.client("cloudfront")
    public_key_id = _create_public_key(ctx, cf)

    name_a = ctx.unique_name("sim2real-cf-kg-a-")
    name_b = ctx.unique_name("sim2real-cf-kg-b-")

    group_a_id, _ = _create_key_group(ctx, cf, name_a, public_key_id)
    group_b_id, group_b_etag = _create_key_group(ctx, cf, name_b, public_key_id)

    # Break exactly one thing: try to rename group B to the name already used
    # by group A.
    code, message = _error(
        lambda: cf.update_key_group(
            Id=group_b_id,
            IfMatch=group_b_etag,
            KeyGroupConfig={"Name": name_a, "Items": [public_key_id]},
        )
    )
    assert code == "KeyGroupAlreadyExists", f"expected KeyGroupAlreadyExists, got {code!r}"
    expected_message = "Another key group with the same name already exists within the aws account."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: group B still has its original name, and the rejected write
    # did not advance its version either.
    still = cf.get_key_group(Id=group_b_id)
    still_name = still["KeyGroup"]["KeyGroupConfig"]["Name"]
    assert still_name == name_b, f"expected group B name unchanged at {name_b!r}, got {still_name!r}"
    assert still["ETag"] == group_b_etag, (
        f"expected ETag unchanged at {group_b_etag!r} after a rejected UpdateKeyGroup, "
        f"got {still['ETag']!r}"
    )
    group_b_etag = still["ETag"]

    # Positive control: renaming to a genuinely unused name succeeds.
    name_c = ctx.unique_name("sim2real-cf-kg-c-")
    cf.update_key_group(
        Id=group_b_id,
        IfMatch=group_b_etag,
        KeyGroupConfig={"Name": name_c, "Items": [public_key_id]},
    )
    renamed = cf.get_key_group(Id=group_b_id)
    renamed_name = renamed["KeyGroup"]["KeyGroupConfig"]["Name"]
    assert renamed_name == name_c, f"expected group B renamed to {name_c!r}, got {renamed_name!r}"


def _error(fn):
    """Call fn(); return the botocore error (code, message). An unexpected success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response["Error"]
        return err["Code"], err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _generate_rsa_public_key_pem() -> str:
    try:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import rsa

        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        pem = key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return pem.decode("ascii")
    except ImportError:
        pass

    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as tmp:
        priv_path = Path(tmp) / "key.pem"
        pub_path = Path(tmp) / "key.pub.pem"
        subprocess.run(
            ["openssl", "genrsa", "-out", str(priv_path), "2048"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "rsa", "-in", str(priv_path), "-pubout", "-out", str(pub_path)],
            check=True, capture_output=True,
        )
        return pub_path.read_text()


def _create_public_key(ctx, cf) -> str:
    pem = _generate_rsa_public_key_pem()
    resp = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-cf-pk-"),
            "Name": ctx.unique_name("sim2real-cf-pk-"),
            "EncodedKey": pem,
            "Comment": "sim2real behavioral check",
        }
    )
    key_id = resp["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_public_key(Id=key_id, IfMatch=cf.get_public_key(Id=key_id)["ETag"]))
    return key_id


def _create_key_group(ctx, cf, name: str, public_key_id: str):
    resp = cf.create_key_group(KeyGroupConfig={"Name": name, "Items": [public_key_id]})
    group_id = resp["KeyGroup"]["Id"]
    ctx.on_cleanup(
        lambda: cf.delete_key_group(Id=group_id, IfMatch=cf.get_key_group(Id=group_id)["ETag"])
    )
    return group_id, resp["ETag"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
