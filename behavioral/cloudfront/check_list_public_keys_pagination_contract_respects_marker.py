"""list-public-keys-pagination-contract-respects-marker."""
from __future__ import annotations

import subprocess

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "list-public-keys-pagination-contract-respects-marker"
GROUP = "server-side"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPublicKeys with MaxItems=1 must resume from the exact next item across repeated
    calls (using NextMarker), visiting every created key exactly once -- no duplication and
    no gaps."""
    require_tools("openssl")
    cf = ctx.client("cloudfront")

    created_ids: set[str] = set()
    for _ in range(3):
        pem = _generate_rsa_public_key_pem()
        ref = ctx.unique_name("sim2real-pubkey-")
        key = cf.create_public_key(
            PublicKeyConfig={
                "CallerReference": ref,
                "Name": ref,
                "EncodedKey": pem,
                "Comment": "sim2real-behav cloudfront check",
            }
        )["PublicKey"]
        key_id = key["Id"]
        created_ids.add(key_id)
        ctx.on_cleanup(lambda kid=key_id: cf.delete_public_key(Id=kid, IfMatch=_current_etag(cf, kid)))

    seen: list[str] = []
    marker = None
    for _ in range(10_000):  # hard upper bound so a broken NextMarker loop can't hang forever
        kwargs = {"MaxItems": "1"}  # CloudFront's legacy pagination API models MaxItems as a string
        if marker:
            kwargs["Marker"] = marker
        page = cf.list_public_keys(**kwargs)["PublicKeyList"]
        items = page.get("Items", [])
        assert len(items) <= 1, f"MaxItems=1 but page returned {len(items)} items"
        seen.extend(item["Id"] for item in items)
        marker = page.get("NextMarker")
        if not marker:
            break

    assert len(seen) == len(set(seen)), f"pagination walk produced duplicate IDs: {seen}"
    missing = created_ids - set(seen)
    assert not missing, f"pagination walk skipped created keys: {missing}"


def _generate_rsa_public_key_pem() -> str:
    priv = subprocess.run(
        ["openssl", "genrsa", "2048"], capture_output=True, check=True, timeout=30
    ).stdout
    pub = subprocess.run(
        ["openssl", "rsa", "-pubout"], input=priv, capture_output=True, check=True, timeout=30
    ).stdout
    return pub.decode("ascii")


def _current_etag(cf, key_id: str) -> str:
    return cf.get_public_key(Id=key_id)["ETag"]


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
