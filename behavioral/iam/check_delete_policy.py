"""delete-policy."""
from __future__ import annotations

from botocore.exceptions import ClientError

import json

from behavioral_harness import tags

MINIMAL_POLICY_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "iam:GetUser",
                "Resource": "arn:aws:iam::*:user/sim2real-behav-*",
            }
        ],
    }
)

CHECK = "delete-policy"
GROUP = 'policy_lifecycle'
SERVICES = ['iam']

ERR_NO_SUCH_ENTITY = "NoSuchEntity"

def _error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _delete_tolerating_not_found(iam, arn):
    """Cleanup: delete the policy, accepting that the body already deleted it."""
    try:
        iam.delete_policy(PolicyArn=arn)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != ERR_NO_SUCH_ENTITY:
            raise


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DeletePolicy removes the policy: GetPolicy then raises NoSuchEntity, a mutation on the
    dead ARN (CreatePolicyVersion) also raises NoSuchEntity, and the freed policy name is
    reusable by CreatePolicy with the identical ARN."""
    iam = ctx.client("iam")
    policy_name = ctx.unique_name("sim2real-behav-pol-")
    arn = iam.create_policy(PolicyName=policy_name, PolicyDocument=MINIMAL_POLICY_DOCUMENT, Path="/")["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=arn: _delete_tolerating_not_found(iam, a))
    iam.delete_policy(PolicyArn=arn)
    expected = f"Policy {arn} was not found."

    get_code, get_message = _error(lambda: iam.get_policy(PolicyArn=arn))
    assert get_code == ERR_NO_SUCH_ENTITY, f"GetPolicy after delete: expected {ERR_NO_SUCH_ENTITY}, got {get_code}"
    assert get_message == expected, f"GetPolicy after delete: expected message {expected!r}, got {get_message!r}"

    version_code, version_message = _error(
        lambda: iam.create_policy_version(PolicyArn=arn, PolicyDocument=MINIMAL_POLICY_DOCUMENT, SetAsDefault=True)
    )
    assert version_code == ERR_NO_SUCH_ENTITY, (
        f"CreatePolicyVersion on a deleted policy: expected {ERR_NO_SUCH_ENTITY}, got {version_code}"
    )
    expected_version = f"Policy {arn} does not exist or is not attachable."
    assert version_message == expected_version, (
        f"CreatePolicyVersion on a deleted policy: expected message {expected_version!r}, got {version_message!r}"
    )

    reused_arn = iam.create_policy(PolicyName=policy_name, PolicyDocument=MINIMAL_POLICY_DOCUMENT, Path="/")["Policy"]["Arn"]
    ctx.on_cleanup(lambda a=reused_arn: _delete_tolerating_not_found(iam, a))
    assert reused_arn == arn, f"freed policy name should be reusable with the identical ARN, got {reused_arn} vs {arn}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
