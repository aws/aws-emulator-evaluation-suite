"""registry-policy-unicode-document-round-trip."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "registry-policy-unicode-document-round-trip"
GROUP = "representation"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-policy")
def run(ctx) -> None:
    """PutRegistryPolicy/GetRegistryPolicy round-trip a policy with unicode values and nested
    Condition maps (including list-valued operators) without loss of structure or content."""
    ecr = ctx.client("ecr")
    sts = ctx.client("sts")
    account_id = sts.get_caller_identity()["Account"]

    original_text, had_policy = _get_registry_policy(ecr)

    def _restore():
        if had_policy:
            ecr.put_registry_policy(policyText=original_text)
        else:
            try:
                ecr.delete_registry_policy()
            except ClientError as exc:
                if exc.response["Error"]["Code"] != "RegistryPolicyNotFoundException":
                    raise

    ctx.on_cleanup(_restore)

    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowReplicationUnicodeTest01",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": ["ecr:ReplicateImage", "ecr:DescribeRepositories"],
                "Resource": "*",
                "Condition": {
                    "StringEquals": {"aws:ResourceTag/环境": "生产-🚀-Ünïçødé"},
                    "StringLike": {
                        "aws:SourceArn": [f"arn:aws:ecr:*:{account_id}:repository/日本語*", "テスト-*"]
                    },
                    "Null": {"aws:MultiFactorAuthAge": "false"},
                },
            },
            {
                "Sid": "AllowDownloadNested02",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "ecr:GetDownloadUrlForLayer",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalTag/team": ["核心团队", "back-end"]}},
            },
        ],
    }

    ecr.put_registry_policy(policyText=json.dumps(policy, ensure_ascii=False))
    get_resp = ecr.get_registry_policy()
    round_tripped = json.loads(get_resp["policyText"])

    def _canonical(d):
        return json.dumps(d, sort_keys=True, ensure_ascii=False)

    assert _canonical(round_tripped) == _canonical(policy), (
        f"policy document changed shape across round trip: expected {_canonical(policy)!r}, "
        f"got {_canonical(round_tripped)!r}"
    )
    assert "生产-🚀-Ünïçødé" in get_resp["policyText"], (
        f"expected literal unicode condition value '生产-🚀-Ünïçødé' preserved unescaped in "
        f"policyText, got {get_resp['policyText']!r}"
    )
    assert "核心团队" in get_resp["policyText"], (
        f"expected literal unicode principal-tag value '核心团队' preserved unescaped in "
        f"policyText, got {get_resp['policyText']!r}"
    )


def _get_registry_policy(ecr):
    try:
        return ecr.get_registry_policy()["policyText"], True
    except ClientError as e:
        if e.response["Error"]["Code"] == "RegistryPolicyNotFoundException":
            return None, False
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
