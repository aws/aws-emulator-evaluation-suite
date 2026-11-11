"""registry-policy-document-unicode-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "registry-policy-document-unicode-round-trip"
GROUP = "representation"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-policy")
def run(ctx) -> None:
    """A registry policy containing unicode characters and nested statements round-trips
    through PutRegistryPolicy/GetRegistryPolicy with the unicode content preserved exactly."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    original = _get_registry_policy_text(ecr)

    def _restore():
        if original is None:
            _delete_registry_policy_ignore_missing(ecr)
        else:
            ecr.put_registry_policy(policyText=original)

    ctx.on_cleanup(_restore)

    unicode_value = "\u65e5\u672c\u8a9e\u30c6\u30b9\u30c8 \u2013 fa\u00e7ade \u2013 \U0001F680 \u2013 \u00dcn\u00efc\u00f6d\u00e9 \u2013 \u0422\u0435\u0441\u0442\u043e\u0432\u044b\u0439"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowReplicateFromSelf",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "ecr:ReplicateImage",
                "Resource": f"arn:aws:ecr:{ctx.region}:{account_id}:repository/*",
            },
            {
                "Sid": "AllowCreateRepoWithUnicodeCondition",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "ecr:CreateRepository",
                "Resource": f"arn:aws:ecr:{ctx.region}:{account_id}:repository/*",
                "Condition": {
                    "StringEquals": {"aws:RequestTag/Owner": unicode_value}
                },
            },
        ],
    }
    policy_text = json.dumps(policy, ensure_ascii=False)

    ecr.put_registry_policy(policyText=policy_text)
    fetched_text = ecr.get_registry_policy()["policyText"]
    fetched = json.loads(fetched_text)

    assert fetched == policy, f"policy round-trip mismatch: expected {policy!r}, got {fetched!r}"
    assert len(fetched["Statement"]) == 2, (
        f"expected 2 statements after round-trip, got {len(fetched['Statement'])}"
    )
    nested_value = fetched["Statement"][1]["Condition"]["StringEquals"]["aws:RequestTag/Owner"]
    assert nested_value == unicode_value, (
        f"unicode condition value corrupted: expected {unicode_value!r}, got {nested_value!r}"
    )


def _get_registry_policy_text(ecr):
    try:
        return ecr.get_registry_policy()["policyText"]
    except ecr.exceptions.RegistryPolicyNotFoundException:
        return None


def _delete_registry_policy_ignore_missing(ecr) -> None:
    try:
        ecr.delete_registry_policy()
    except ecr.exceptions.RegistryPolicyNotFoundException:
        pass


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
