"""list-field-level-encryption-profiles-pagination-walks-full-set."""
from __future__ import annotations

import subprocess

from behavioral_harness import tags

CHECK = "list-field-level-encryption-profiles-pagination-walks-full-set"
GROUP = "pagination"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListFieldLevelEncryptionProfiles with MaxItems=1 pages through Marker/NextMarker and the
    pages together cover exactly the created profiles, each exactly once."""
    from fidelity_tests_runner import require_tools

    require_tools("openssl")

    cf = ctx.client("cloudfront")
    pk_id = _create_public_key(ctx, cf)

    created_ids = [_create_profile(ctx, cf, pk_id, index) for index in range(3)]
    created_set = set(created_ids)
    assert len(created_set) == 3, f"expected 3 distinct profile ids, got {created_ids!r}"

    seen: list[str] = []
    marker = ""
    pages = 0
    max_pages = 200
    while pages < max_pages:
        pages += 1
        page = cf.list_field_level_encryption_profiles(Marker=marker, MaxItems="1")
        body = page["FieldLevelEncryptionProfileList"]
        items = body.get("Items", [])
        assert len(items) <= 1, f"MaxItems=1 but page {pages} returned {len(items)} item(s): {items!r}"
        seen.extend(item["Id"] for item in items)
        next_marker = body.get("NextMarker")
        if next_marker is None:
            break
        assert next_marker != marker, f"NextMarker {next_marker!r} did not advance past Marker {marker!r}"
        marker = next_marker
    else:
        raise AssertionError(f"did not reach the end of the list within {max_pages} pages")

    seen_of_ours = [i for i in seen if i in created_set]
    assert sorted(seen_of_ours) == sorted(created_ids), (
        f"walking every page with MaxItems=1 should surface each created profile exactly once, "
        f"created={sorted(created_ids)!r} seen={sorted(seen_of_ours)!r}"
    )
    assert len(seen_of_ours) == len(set(seen_of_ours)), (
        f"a profile id appeared on more than one page while walking with MaxItems=1: {seen_of_ours!r}"
    )


def _create_public_key(ctx, cf) -> str:
    priv = subprocess.run(["openssl", "genrsa", "2048"], capture_output=True, check=True).stdout
    pem = subprocess.run(["openssl", "rsa", "-pubout"], input=priv, capture_output=True, check=True).stdout.decode(
        "ascii"
    )
    ref = ctx.unique_name("sim2real-fle-pg-pk-")
    pk = cf.create_public_key(
        PublicKeyConfig={"CallerReference": ref, "Name": ref, "EncodedKey": pem, "Comment": "sim2real-behav"}
    )
    pk_id = pk["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: cf.delete_public_key(Id=pk_id, IfMatch=cf.get_public_key(Id=pk_id)["ETag"]))
    return pk_id


def _create_profile(ctx, cf, pk_id: str, index: int) -> str:
    ref = ctx.unique_name(f"sim2real-fle-pg-profile-{index}-")
    created = cf.create_field_level_encryption_profile(
        FieldLevelEncryptionProfileConfig={
            "Name": ref,
            "CallerReference": ref,
            "Comment": "sim2real-behav pagination",
            "EncryptionEntities": {
                "Quantity": 1,
                "Items": [
                    {
                        "PublicKeyId": pk_id,
                        "ProviderId": "sim2real-provider",
                        "FieldPatterns": {"Quantity": 1, "Items": [f"Field{index}"]},
                    }
                ],
            },
        }
    )
    profile_id = created["FieldLevelEncryptionProfile"]["Id"]

    def _cleanup() -> None:
        try:
            etag = cf.get_field_level_encryption_profile_config(Id=profile_id)["ETag"]
        except cf.exceptions.NoSuchFieldLevelEncryptionProfile:
            return
        cf.delete_field_level_encryption_profile(Id=profile_id, IfMatch=etag)

    ctx.on_cleanup(_cleanup)
    return profile_id


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
