"""update-key-group-duplicate-name-rejected."""
from __future__ import annotations

import os
import subprocess
import tempfile

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "update-key-group-duplicate-name-rejected"
GROUP = "overly-permissive"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Renaming a key group via UpdateKeyGroup to a name already used by another key group
    is rejected with KeyGroupAlreadyExists, not silently accepted; renaming to a genuinely
    unique name still succeeds."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    cf = ctx.client("cloudfront")
    public_key_id = _create_public_key(ctx)

    name_a = ctx.unique_name("sim2real-kga-")
    name_b = ctx.unique_name("sim2real-kgb-")
    _group_a_id, _group_a_etag = _create_key_group(ctx, name_a, public_key_id)
    group_b_id, group_b_etag = _create_key_group(ctx, name_b, public_key_id)

    code, message = _error(
        lambda: cf.update_key_group(
            Id=group_b_id, KeyGroupConfig={"Name": name_a, "Items": [public_key_id]}, IfMatch=group_b_etag
        )
    )
    assert code == "KeyGroupAlreadyExists", f"expected KeyGroupAlreadyExists, got {code!r}"
    expected_message = "Another key group with the same name already exists within the aws account."
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: group B still has its own name, version unchanged.
    after = cf.get_key_group(Id=group_b_id)
    assert after["KeyGroup"]["KeyGroupConfig"]["Name"] == name_b, (
        f"expected group B's name to remain {name_b!r} after the rejected rename, "
        f"got {after['KeyGroup']['KeyGroupConfig']['Name']!r}"
    )
    assert after["ETag"] == group_b_etag, (
        f"expected group B's ETag to remain {group_b_etag!r} after the rejected rename, "
        f"got {after['ETag']!r}"
    )

    # Positive control: renaming to a genuinely unique name succeeds. Assert via an
    # independent read (GetKeyGroup), not the mutating call's own response.
    name_c = ctx.unique_name("sim2real-kgc-")
    cf.update_key_group(
        Id=group_b_id, KeyGroupConfig={"Name": name_c, "Items": [public_key_id]}, IfMatch=group_b_etag
    )
    renamed = cf.get_key_group(Id=group_b_id)
    assert renamed["KeyGroup"]["KeyGroupConfig"]["Name"] == name_c, (
        f"expected group B's name to be {name_c!r} after the successful rename, "
        f"got {renamed['KeyGroup']['KeyGroupConfig']['Name']!r}"
    )


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
    with tempfile.TemporaryDirectory() as d:
        key_path = os.path.join(d, "key.pem")
        pub_path = os.path.join(d, "pub.pem")
        subprocess.run(["openssl", "genrsa", "-out", key_path, "2048"], check=True, capture_output=True)
        subprocess.run(
            ["openssl", "rsa", "-in", key_path, "-pubout", "-out", pub_path], check=True, capture_output=True
        )
        with open(pub_path) as f:
            return f.read()


def _create_public_key(ctx) -> str:
    cf = ctx.client("cloudfront")
    pub_pem = _generate_rsa_public_key_pem()
    resp = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-pk-"),
            "Name": ctx.unique_name("sim2real-pk-"),
            "EncodedKey": pub_pem,
            "Comment": "sim2real test key",
        }
    )
    key_id = resp["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _delete_public_key(ctx, key_id))
    return key_id


def _delete_public_key(ctx, key_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_public_key(Id=key_id)["ETag"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicKey":
            raise
        return
    cf.delete_public_key(Id=key_id, IfMatch=etag)


def _create_key_group(ctx, name: str, public_key_id: str):
    cf = ctx.client("cloudfront")
    resp = cf.create_key_group(KeyGroupConfig={"Name": name, "Items": [public_key_id]})
    key_group_id = resp["KeyGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_key_group(ctx, key_group_id))
    return key_group_id, resp["ETag"]


def _delete_key_group(ctx, key_group_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_key_group(Id=key_group_id)["ETag"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchResource":
            raise
        return
    cf.delete_key_group(Id=key_group_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
