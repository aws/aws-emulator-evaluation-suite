"""op-contract-getGroupPolicy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getGroupPolicy"
GROUP = "error-semantics"
SERVICES = ["iam"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetGroupPolicy returns the exact inline policy document that was written with
    PutGroupPolicy; a policy name that was never attached to the group is rejected."""
    iam = ctx.client("iam")
    group_name = ctx.unique_name("sim2real-iam-ggp-")
    iam.create_group(GroupName=group_name)
    ctx.on_cleanup(lambda: iam.delete_group(GroupName=group_name))
    policy_doc = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}]}
    iam.put_group_policy(GroupName=group_name, PolicyName="inline", PolicyDocument=json.dumps(policy_doc))
    ctx.on_cleanup(lambda: iam.delete_group_policy(GroupName=group_name, PolicyName="inline"))

    resp = iam.get_group_policy(GroupName=group_name, PolicyName="inline")
    assert resp["GroupName"] == group_name, f"expected GroupName {group_name!r}, got {resp['GroupName']!r}"
    assert resp["PolicyName"] == "inline", f"expected PolicyName 'inline', got {resp['PolicyName']!r}"
    assert resp["PolicyDocument"]["Statement"][0]["Action"] == "s3:ListBucket", resp["PolicyDocument"]

    # positive control already exercised above; now confirm the negative boundary:
    # a policy name that was never attached to this (real, existing) group is rejected.
    # IAM's wire-level Code for this shape is "NoSuchEntity" (the modeled exception
    # class name "NoSuchEntityException" is not the on-the-wire Code).
    code, message = _error(
        lambda: iam.get_group_policy(GroupName=group_name, PolicyName="does-not-exist")
    )
    assert code == "NoSuchEntity", f"expected NoSuchEntity, got {code!r}"
    expected = "The group policy with name does-not-exist cannot be found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"


def _error(fn):
    """Call fn(); return (Error.Code, Error.Message) of the ClientError it raises, else raise."""
    try:
        result = fn()
    except ClientError as e:
        return e.response["Error"]["Code"], e.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
