"""concurrent-update-key-group-conflicting-etag."""
from __future__ import annotations

import os
import subprocess
import tempfile
from concurrent.futures import ThreadPoolExecutor

from behavioral_harness import tags
from fidelity_tests_runner import require_tools

CHECK = "concurrent-update-key-group-conflicting-etag"
GROUP = "concurrency"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Two concurrent UpdateKeyGroup calls from the same ETag: exactly one wins, the loser is
    rejected as stale, the final state matches the winner, and the current ETag still updates."""
    from botocore.exceptions import ClientError

    cf = ctx.client("cloudfront")

    pem = _generate_rsa_public_key_pem()
    pub_resp = cf.create_public_key(
        PublicKeyConfig={
            "CallerReference": ctx.unique_name("sim2real-pkref-"),
            "Comment": "sim2real behavioral check",
            "EncodedKey": pem,
            "Name": ctx.unique_name("sim2real-pubkey-"),
        }
    )
    pub_key_id = pub_resp["PublicKey"]["Id"]
    ctx.on_cleanup(lambda: _delete_public_key(ctx, pub_key_id))

    kg_resp = cf.create_key_group(
        KeyGroupConfig={
            "Comment": "initial",
            "Items": [pub_key_id],
            "Name": ctx.unique_name("sim2real-keygroup-"),
        }
    )
    key_group_id = kg_resp["KeyGroup"]["Id"]
    etag = kg_resp["ETag"]
    kg_name = kg_resp["KeyGroup"]["KeyGroupConfig"]["Name"]
    ctx.on_cleanup(lambda: _delete_key_group(ctx, key_group_id))

    def update_with(comment: str):
        return cf.update_key_group(
            Id=key_group_id,
            IfMatch=etag,
            KeyGroupConfig={
                "Comment": comment,
                "Items": [pub_key_id],
                "Name": kg_name,
            },
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        fut_a = pool.submit(update_with, "winner-a")
        fut_b = pool.submit(update_with, "winner-b")
        results = []
        for fut, tag in ((fut_a, "a"), (fut_b, "b")):
            try:
                resp = fut.result()
                results.append((tag, "ok", resp))
            except ClientError as exc:
                results.append((tag, exc.response["Error"]["Code"], exc.response["Error"].get("Message")))

    oks = [r for r in results if r[1] == "ok"]
    fails = [r for r in results if r[1] != "ok"]
    assert len(oks) == 1, f"expected exactly one winner, got {results}"
    assert len(fails) == 1, f"expected exactly one loser, got {results}"
    # A syntactically well-formed but now-stale ETag is a precondition failure
    # (HTTP 412), not a malformed/missing If-Match header (InvalidIfMatchVersion).
    assert fails[0][1] in ("PreconditionFailed", "InvalidIfMatchVersion"), (
        f"loser should be rejected with PreconditionFailed, got {fails[0][1]}"
    )
    if fails[0][1] == "PreconditionFailed":
        assert fails[0][2] == "The request failed because it didn't meet the preconditions for this operation.", (
            f"UpdateKeyGroup PreconditionFailed message: {fails[0][2]!r}"
        )

    winner_comment = "winner-a" if oks[0][0] == "a" else "winner-b"
    final = cf.get_key_group(Id=key_group_id)
    final_config = final["KeyGroup"]["KeyGroupConfig"]
    assert final_config["Comment"] == winner_comment, (
        f"final state {final_config['Comment']!r} does not match the actual winner "
        f"{winner_comment!r} -- update was not atomic"
    )

    # Restore leg: the rejection must be a precondition failure, not a permanent
    # wedge -- an identical call carrying the now-current ETag must succeed.
    restore_resp = cf.update_key_group(
        Id=key_group_id,
        IfMatch=final["ETag"],
        KeyGroupConfig={
            "Comment": "post-race-restore",
            "Items": [pub_key_id],
            "Name": kg_name,
        },
    )
    assert restore_resp["ETag"] != final["ETag"], (
        "update with the current ETag after the race should succeed and mint a "
        "new ETag -- optimistic locking must not permanently wedge the resource"
    )
    restored = cf.get_key_group(Id=key_group_id)["KeyGroup"]["KeyGroupConfig"]
    assert restored["Comment"] == "post-race-restore", (
        f"expected the post-race restore update to take effect, got {restored['Comment']!r}"
    )


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

    require_tools("openssl")
    with tempfile.TemporaryDirectory() as d:
        priv = os.path.join(d, "k.pem")
        pub = os.path.join(d, "pub.pem")
        subprocess.run(
            ["openssl", "genrsa", "-out", priv, "2048"],
            check=True, capture_output=True,
        )
        subprocess.run(
            ["openssl", "rsa", "-in", priv, "-pubout", "-out", pub],
            check=True, capture_output=True,
        )
        with open(pub) as f:
            return f.read()


def _delete_public_key(ctx, key_id: str) -> None:
    cf = ctx.client("cloudfront")
    etag = cf.get_public_key(Id=key_id)["ETag"]
    cf.delete_public_key(Id=key_id, IfMatch=etag)


def _delete_key_group(ctx, group_id: str) -> None:
    cf = ctx.client("cloudfront")
    etag = cf.get_key_group(Id=group_id)["ETag"]
    cf.delete_key_group(Id=group_id, IfMatch=etag)


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
