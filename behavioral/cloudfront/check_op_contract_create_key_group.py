"""op-contract-createKeyGroup."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createKeyGroup"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateKeyGroup returns, and GetKeyGroup reads back, its Name and single public key; a second create
    with that Name is refused with KeyGroupAlreadyExists and the exact message, ListKeyGroups shows the name
    once, and the same create succeeds with a new Id once the first group is deleted."""

    cf = ctx.client("cloudfront")
    pem = _generate_rsa_public_key_pem()

    public_key_id = _create_public_key(ctx, pem)

    name = ctx.unique_name("sim2real-keygroup-")
    resp = cf.create_key_group(
        KeyGroupConfig={
            "Name": name,
            "Items": [public_key_id],
            "Comment": "sim2real behavioral check",
        }
    )
    group = resp["KeyGroup"]
    group_id = group["Id"]
    ctx.on_cleanup(lambda: _delete_key_group(ctx, group_id))

    assert group_id, "expected CreateKeyGroup to return a non-empty Id"
    assert group["KeyGroupConfig"]["Name"] == name, (
        f"expected echoed Name {name!r}, got {group['KeyGroupConfig']['Name']!r}"
    )
    assert group["KeyGroupConfig"]["Items"] == [public_key_id], (
        f"expected echoed Items [{public_key_id!r}], got {group['KeyGroupConfig']['Items']!r}"
    )
    assert resp.get("ETag"), "expected an ETag on create"
    assert resp.get("Location"), "expected a Location header value"

    # Independent read at the destination: the create response is an echo, not proof of
    # persistence. GetKeyGroup goes through a distinct operation.
    got = cf.get_key_group(Id=group_id)
    assert got["KeyGroup"]["KeyGroupConfig"]["Name"] == name, (
        f"GetKeyGroup Name mismatch: expected {name!r}, got "
        f"{got['KeyGroup']['KeyGroupConfig']['Name']!r}"
    )
    assert got["KeyGroup"]["KeyGroupConfig"]["Items"] == [public_key_id], (
        f"GetKeyGroup Items mismatch: expected [{public_key_id!r}], got "
        f"{got['KeyGroup']['KeyGroupConfig']['Items']!r}"
    )
    assert got["ETag"], "expected GetKeyGroup to return an ETag"

    # A second key group with the same Name is refused with KeyGroupAlreadyExists and leaves only
    # the original; once the original is deleted, the identical create succeeds.
    dup_config = {"Name": name, "Items": [public_key_id], "Comment": "dup"}
    code, message = _error(lambda: cf.create_key_group(KeyGroupConfig=dup_config))
    assert code == "KeyGroupAlreadyExists", f"expected KeyGroupAlreadyExists, got {code}"
    expected = "Another key group with the same name already exists within the aws account."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    listing = cf.list_key_groups()
    matches = [
        item
        for item in listing.get("KeyGroupList", {}).get("Items", [])
        if item["KeyGroup"]["KeyGroupConfig"]["Name"] == name
    ]
    assert len(matches) == 1, (
        f"expected exactly 1 key group named {name!r} after the rejected duplicate, "
        f"found {len(matches)}"
    )
    assert matches[0]["KeyGroup"]["Id"] == group_id, (
        f"expected the surviving key group to be the original {group_id!r}, "
        f"got {matches[0]['KeyGroup']['Id']!r}"
    )

    etag = cf.get_key_group(Id=group_id)["ETag"]
    cf.delete_key_group(Id=group_id, IfMatch=etag)

    restore_resp = cf.create_key_group(KeyGroupConfig=dup_config)
    restored_id = restore_resp["KeyGroup"]["Id"]
    ctx.on_cleanup(lambda: _delete_key_group(ctx, restored_id))
    assert restored_id and restored_id != group_id, (
        f"expected a freshly restored key group with a new Id, got {restored_id!r}"
    )

    restored = cf.get_key_group(Id=restored_id)
    assert restored["KeyGroup"]["KeyGroupConfig"]["Name"] == name, (
        f"expected the restored key group's Name to be {name!r}, got "
        f"{restored['KeyGroup']['KeyGroupConfig']['Name']!r}"
    )


def _generate_rsa_public_key_pem() -> str:
    import os
    import subprocess
    import tempfile

    from fidelity_tests_runner import require_tools

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        priv = os.path.join(d, "priv.pem")
        pub = os.path.join(d, "pub.pem")
        subprocess.run(["openssl", "genrsa", "-out", priv, "2048"], check=True, capture_output=True)
        subprocess.run(["openssl", "rsa", "-in", priv, "-pubout", "-out", pub], check=True, capture_output=True)
        with open(pub) as f:
            return f.read()


def _create_public_key(ctx, pem: str) -> str:
    cf = ctx.client("cloudfront")
    resp = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-keygroup-pubkey-"),
            "Name": ctx.unique_name("sim2real-keygroup-pubkey-"),
            "EncodedKey": pem,
            "Comment": "sim2real behavioral check (for key group)",
        }
    )
    key_id = resp["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _delete_public_key(ctx, key_id))
    return key_id


def _delete_public_key(ctx, key_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_public_key(Id=key_id)["ETag"]
        cf.delete_public_key(Id=key_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchPublicKey":
            raise


def _delete_key_group(ctx, group_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_key_group(Id=group_id)["ETag"]
        cf.delete_key_group(Id=group_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchResource":
            raise


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected success raises,
    so a target that accepts what AWS refuses fails as an accepted call, not as a code mismatch."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
