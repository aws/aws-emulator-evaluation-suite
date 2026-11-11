"""registry-policy-unicode-round-trip."""
from __future__ import annotations

import json
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "registry-policy-unicode-round-trip"
GROUP = "representation"
SERVICES = ["ecr"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:ecr-registry-policy")
def run(ctx) -> None:
    """Unicode and special characters embedded in a registry policy JSON document survive
    put/get unchanged."""
    ecr = ctx.client("ecr")
    account_id = ctx.client("sts").get_caller_identity()["Account"]

    baseline = _get_registry_policy(ecr)

    def _restore():
        try:
            ecr.delete_registry_policy()
        except ClientError as e:
            if e.response["Error"]["Code"] != "RegistryPolicyNotFoundException":
                raise
        if baseline is not None:
            ecr.put_registry_policy(policyText=baseline)

    ctx.on_cleanup(_restore)

    unicode_value = f"sim2real-测试团队-🚀-héllo-{uuid.uuid4().hex[:6]}"
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "AllowUnicodeConditionTest",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "ecr:DescribeRepositories",
                "Resource": "*",
                "Condition": {"StringEquals": {"aws:PrincipalTag/team": unicode_value}},
            }
        ],
    }
    policy_text = json.dumps(policy, ensure_ascii=False)

    put_resp = ecr.put_registry_policy(policyText=policy_text)
    put_policy = json.loads(put_resp["policyText"])
    put_value = put_policy["Statement"][0]["Condition"]["StringEquals"]["aws:PrincipalTag/team"]
    assert put_value == unicode_value, (
        f"put_registry_policy echoed condition value {put_value!r}, expected {unicode_value!r}"
    )

    get_resp = ecr.get_registry_policy()
    get_policy = json.loads(get_resp["policyText"])
    assert get_policy == policy, (
        f"registry policy document changed shape across round trip: got {get_policy!r}, "
        f"expected {policy!r}"
    )
    get_value = get_policy["Statement"][0]["Condition"]["StringEquals"]["aws:PrincipalTag/team"]
    assert get_value == unicode_value, (
        f"get_registry_policy returned condition value {get_value!r}, expected {unicode_value!r}"
    )


def _get_registry_policy(ecr):
    try:
        return ecr.get_registry_policy()["policyText"]
    except ClientError as e:
        if e.response["Error"]["Code"] == "RegistryPolicyNotFoundException":
            return None
        raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
