"""get-key-policy-default."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "get-key-policy-default"
GROUP = 'key_policy'
SERVICES = ['kms']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A key created without a Policy gets a default key policy with an Allow statement granting
    the account root ("arn:aws:iam::<account>:root") "kms:*"."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]
    root_arn = f"arn:aws:iam::{account_id}:root"

    key_id = kms.create_key(
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
        Tags=[{"TagKey": "sim2real", "TagValue": "get-key-policy-default"}],
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda _k=key_id: kms.schedule_key_deletion(KeyId=_k, PendingWindowInDays=7))

    resp = kms.get_key_policy(KeyId=key_id, PolicyName="default")
    policy = json.loads(resp["Policy"])
    statements = policy["Statement"]
    assert isinstance(statements, list) and statements, (
        f"expected a non-empty Statement list in the default policy, got {statements!r}"
    )

    def _grants_root_full_access(stmt: dict) -> bool:
        if stmt.get("Effect") != "Allow":
            return False
        principal = stmt.get("Principal", {})
        principal_aws = principal.get("AWS") if isinstance(principal, dict) else None
        principal_aws_list = principal_aws if isinstance(principal_aws, list) else [principal_aws]
        if root_arn not in principal_aws_list:
            return False
        action = stmt.get("Action")
        action_list = action if isinstance(action, list) else [action]
        return "kms:*" in action_list

    root_stmt = next((s for s in statements if _grants_root_full_access(s)), None)
    assert root_stmt is not None, (
        f"default key policy has no Allow statement granting {root_arn} kms:*: {statements}"
    )

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
