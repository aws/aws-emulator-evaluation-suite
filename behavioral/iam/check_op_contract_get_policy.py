"""op-contract-getPolicy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-getPolicy"
GROUP = "error-semantics"
SERVICES = ["iam"]

POLICY_DOC = json.dumps({
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Action": "s3:ListAllMyBuckets", "Resource": "*"}],
})


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetPolicy returns a new policy's name, Arn, DefaultVersionId v1 and AttachmentCount
    0; a never-created PolicyArn, and the policy once deleted, fail with NoSuchEntity and
    the exact message."""
    iam = ctx.client("iam")
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    policy_name = ctx.unique_name("sim2real-getpolicy-")
    created = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=POLICY_DOC,
        Tags=[{"Key": "sim2real", "Value": "op-contract-get-policy"}],
    )["Policy"]
    arn = created["Arn"]
    ctx.on_cleanup(lambda: _delete_if_present(iam, arn))

    got = iam.get_policy(PolicyArn=arn)["Policy"]
    assert got["PolicyName"] == policy_name, f"expected PolicyName {policy_name!r}, got {got.get('PolicyName')!r}"
    assert got["DefaultVersionId"] == "v1", f"expected DefaultVersionId v1, got {got.get('DefaultVersionId')!r}"
    assert got["AttachmentCount"] == 0, f"expected AttachmentCount 0, got {got.get('AttachmentCount')!r}"
    assert got["Arn"] == arn, f"expected Arn {arn!r}, got {got.get('Arn')!r}"

    bogus_arn = f"arn:aws:iam::{account_id}:policy/{ctx.unique_name('sim2real-getpolicy-never-')}"
    code, message = _error(lambda: iam.get_policy(PolicyArn=bogus_arn))
    assert code == "NoSuchEntity", f"expected NoSuchEntity for a never-created policy, got {code}"
    expected = f"Policy {bogus_arn} was not found."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    iam.delete_policy(PolicyArn=arn)
    code_after_delete, message_after_delete = _error(lambda: iam.get_policy(PolicyArn=arn))
    assert code_after_delete == "NoSuchEntity", (
        f"expected NoSuchEntity for a deleted policy, got {code_after_delete}"
    )
    expected_after_delete = f"Policy {arn} was not found."
    assert message_after_delete == expected_after_delete, (
        f"expected message {expected_after_delete!r}, got {message_after_delete!r}"
    )


def _delete_if_present(iam, arn):
    from botocore.exceptions import ClientError

    try:
        iam.delete_policy(PolicyArn=arn)
    except ClientError as err:
        if err.response["Error"]["Code"] != "NoSuchEntity":
            raise


def _error(fn) -> tuple[str, str]:
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message", "")
    raise AssertionError(f"expected this call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
