"""key-policy-special-characters-round-trip."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "key-policy-special-characters-round-trip"
GROUP = "server-side"
SERVICES = ["kms"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A key policy JSON document containing unicode, escaped quotes, and nested structures is
    returned with an identical parsed structure from GetKeyPolicy after PutKeyPolicy."""
    kms = ctx.client("kms")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    key_id = kms.create_key(
        Description=ctx.unique_name("sim2real-kms-policy-"),
        KeyUsage="ENCRYPT_DECRYPT",
        KeySpec="SYMMETRIC_DEFAULT",
    )["KeyMetadata"]["KeyId"]
    ctx.on_cleanup(lambda: kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7))

    # NOTE: KMS key policy documents are constrained to the pattern
    # [\u0009\u000A\u000D\u0020-\u00FF]+ (tab/LF/CR plus printable ASCII and the Latin-1
    # supplement block) -- see API_PutKeyPolicy.html. Characters outside \u00FF (e.g. CJK,
    # emoji) are rejected with ValidationException, so this round-trip uses Latin-1-range
    # unicode (accents, currency/section signs) plus escaped quotes and backslashes rather
    # than arbitrary unicode.
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "EnableRootFullAccess",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "kms:*",
                "Resource": "*",
            },
            {
                "Sid": "UnicodeConditionStatement",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["kms:DescribeKey", "kms:GetKeyPolicy"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {
                        "aws:PrincipalTag/department": (
                            'R&D "Special" \u00dcn\u00efc\u00f6d\u00e9 '
                            "caf\u00e9 \u00a9\u00ae\u00a7 line\\nwith\\backslash"
                        )
                    }
                },
            },
        ],
    }
    policy_text = json.dumps(policy, ensure_ascii=False)

    kms.put_key_policy(KeyId=key_id, PolicyName="default", Policy=policy_text)
    returned_text = kms.get_key_policy(KeyId=key_id, PolicyName="default")["Policy"]
    returned_policy = json.loads(returned_text)

    assert returned_policy == policy, f"parsed policy diverged after round-trip: {returned_policy!r} != {policy!r}"
    # KMS may re-serialize the JSON text (e.g. escaping non-ASCII as \uXXXX instead of raw
    # UTF-8 bytes), so a raw substring search on returned_text is not a valid byte-identity
    # check. Instead, confirm the unicode value survives round-trip at the character/codepoint
    # level by comparing it (and its UTF-8 encoding) after re-parsing the returned document.
    unicode_value = policy["Statement"][1]["Condition"]["StringEquals"]["aws:PrincipalTag/department"]
    returned_value = returned_policy["Statement"][1]["Condition"]["StringEquals"]["aws:PrincipalTag/department"]
    assert returned_value == unicode_value, f"unicode condition value diverged: {returned_value!r} != {unicode_value!r}"
    assert returned_value.encode("utf-8") == unicode_value.encode("utf-8"), (
        "unicode condition value must round-trip byte-for-byte at the UTF-8 level"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
