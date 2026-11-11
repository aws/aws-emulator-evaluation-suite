"""list-keys-pagination-marker."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-keys-pagination-marker"
GROUP = 'key_metadata'
SERVICES = ['kms']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListKeys honours Limit and its NextMarker advances to a distinct key."""
    kms = ctx.client("kms")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    for suffix in ("kms-pagea-", "kms-pageb-"):
        kid = kms.create_key(
            Description=ctx.unique_name(suffix),
            KeyUsage="ENCRYPT_DECRYPT",
            KeySpec="SYMMETRIC_DEFAULT",
            Tags=[{"TagKey": "sim2real", "TagValue": "kms-list-keys-pagination-marker"}],
        )["KeyMetadata"]["KeyId"]
        ctx.on_cleanup(lambda _k=kid: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    p1 = kms.list_keys(Limit=1)
    assert len(p1["Keys"]) == 1, p1["Keys"]
    assert p1["Truncated"] is True, p1.get("Truncated")
    assert p1["NextMarker"], "a truncated page must carry NextMarker"
    for entry in p1["Keys"]:
        expected_arn = f"arn:aws:kms:{ctx.region}:{account_id}:key/{entry['KeyId']}"
        assert entry["KeyArn"] == expected_arn, (expected_arn, entry["KeyArn"])

    p2 = kms.list_keys(Limit=1, Marker=p1["NextMarker"])
    assert len(p2["Keys"]) == 1, p2["Keys"]
    assert p2["Keys"][0]["KeyId"] != p1["Keys"][0]["KeyId"], "marker must advance past the first page"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
