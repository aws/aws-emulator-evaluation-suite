"""put-resource-policy-public-policy-rejected."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags

CHECK = "put-resource-policy-public-policy-rejected"
GROUP = "representation"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy with BlockPublicPolicy=True rejects a policy that grants public access;
    the public policy is never attached, while a scoped (non-public) policy in the same file
    still attaches successfully.
    """
    sm = ctx.client("secretsmanager")
    sts = ctx.client("sts")

    name = ctx.unique_name("sim2real-behav-pubpolicy-")
    created = sm.create_secret(Name=name, SecretString="v1")
    arn = created["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    public_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicAllow",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    code, message = _error_code(
        lambda: sm.put_resource_policy(
            SecretId=arn, ResourcePolicy=json.dumps(public_policy), BlockPublicPolicy=True
        )
    )
    assert code == "PublicPolicyException", (
        f"expected PublicPolicyException rejecting a wildcard-principal policy, got {code!r}"
    )
    assert message == (
        "You can not attach a resource policy that grants Public access to your secret."
    ), f"unexpected refusal message: {message!r}"

    # Effect absent: no resource policy should have been attached by the rejected call.
    resp = sm.get_resource_policy(SecretId=arn)
    assert "ResourcePolicy" not in resp, "rejected public policy must not have been attached"

    # Positive control: a scoped policy (principal limited to this account's root) attaches fine.
    account_id = sts.get_caller_identity()["Account"]
    scoped_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "ScopedAllow",
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    sm.put_resource_policy(
        SecretId=arn, ResourcePolicy=json.dumps(scoped_policy), BlockPublicPolicy=True
    )
    ctx.on_cleanup(lambda: sm.delete_resource_policy(SecretId=arn))
    resp2 = sm.get_resource_policy(SecretId=arn)
    attached = json.loads(resp2["ResourcePolicy"])
    assert attached == scoped_policy, (
        f"expected the scoped (non-public) policy to attach unchanged, got {attached!r}"
    )


def _error_code(fn: Callable[[], Any]) -> tuple[str, str | None]:
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
