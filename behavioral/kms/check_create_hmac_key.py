"""create-hmac-key."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-hmac-key"
GROUP = 'key_lifecycle'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateKey (HMAC_256, GENERATE_VERIFY_MAC) is durably recorded at the destination."""
    kms = ctx.client("kms")
    desc = f"sim2real-behav-key-hmac-create-{uuid.uuid4().hex[:8]}"
    resp = kms.create_key(
        Description=desc,
        KeyUsage="GENERATE_VERIFY_MAC",
        KeySpec="HMAC_256",
        Tags=[{"TagKey": "sim2real", "TagValue": "kms-create-hmac-key"}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    meta = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert meta["KeyUsage"] == "GENERATE_VERIFY_MAC", (
        f"expected DescribeKey to report KeyUsage GENERATE_VERIFY_MAC, got {meta['KeyUsage']!r}"
    )
    assert meta["KeySpec"] == "HMAC_256", (
        f"expected DescribeKey to report KeySpec HMAC_256, got {meta['KeySpec']!r}"
    )
    assert meta["Description"] == desc, (
        f"expected DescribeKey to echo the description {desc!r}, got {meta['Description']!r}"
    )
    assert meta["Enabled"] is True, f"expected a freshly created key to be Enabled, got {meta['Enabled']}"

    key_ids = {k["KeyId"] for page in kms.get_paginator("list_keys").paginate() for k in page["Keys"]}
    assert key_id in key_ids, f"expected {key_id} to be visible in ListKeys"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
