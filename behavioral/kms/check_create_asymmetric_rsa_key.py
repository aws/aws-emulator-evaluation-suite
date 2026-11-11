"""create-asymmetric-rsa-key."""
from __future__ import annotations

import uuid

from behavioral_harness import tags

CHECK = "create-asymmetric-rsa-key"
GROUP = 'key_lifecycle'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateKey (RSA_2048, SIGN_VERIFY) is confirmed by an independent DescribeKey read."""
    kms = ctx.client("kms")
    desc = f"sim2real-behav-key-rsa-sign-{uuid.uuid4().hex[:8]}"
    resp = kms.create_key(
        Description=desc,
        KeyUsage="SIGN_VERIFY",
        KeySpec="RSA_2048",
        Tags=[{"TagKey": "sim2real-behav", "TagValue": CHECK}],
    )
    key_id = resp["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    described = kms.describe_key(KeyId=key_id)["KeyMetadata"]
    assert described["KeyUsage"] == "SIGN_VERIFY", f"KeyUsage: {described['KeyUsage']}"
    assert described["KeySpec"] == "RSA_2048", f"KeySpec: {described['KeySpec']}"
    assert described["KeyState"] == "Enabled", f"KeyState: {described['KeyState']}"
    assert described["Description"] == desc, f"Description: {described['Description']}"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
