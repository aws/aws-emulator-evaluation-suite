"""list-aliases."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-aliases"
GROUP = 'aliases'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListAliases includes a newly created alias."""
    kms = ctx.client("kms")
    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": CHECK}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))
    alias_name = f"alias/sim2real-behav-{uuid.uuid4().hex[:8]}"
    kms.create_alias(AliasName=alias_name, TargetKeyId=key_id)
    ctx.on_cleanup(lambda _a=alias_name: kms.delete_alias(AliasName=_a))
    # KMS aliases are eventually consistent — poll until resolvable (restores old create_alias behavior)
    _deadline = time.monotonic() + 15
    while time.monotonic() < _deadline:
        try:
            kms.describe_key(KeyId=alias_name)
            break
        except ClientError:
            time.sleep(0.5)

    found = False
    paginator = kms.get_paginator("list_aliases")
    for page in paginator.paginate(KeyId=key_id):
        for entry in page.get("Aliases", []):
            if entry["AliasName"] == alias_name:
                found = True
                break
        if found:
            break
    assert found, f"Alias {alias_name} not found in ListAliases for key {key_id}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
