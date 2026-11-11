"""op-contract-updateAssumeRolePolicy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-updateAssumeRolePolicy"
GROUP = "error-semantics"
SERVICES = ["iam"]

_INITIAL_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "ec2.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}

_UPDATED_TRUST = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
        }
    ],
}


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UpdateAssumeRolePolicy: the trust document GetRole returns reflects the
    update exactly, and a syntactically invalid document is rejected."""
    iam = ctx.client("iam")
    role_name = ctx.unique_name("sim2real-behav-uarp-")
    iam.create_role(
        RoleName=role_name,
        AssumeRolePolicyDocument=json.dumps(_INITIAL_TRUST),
    )
    ctx.on_cleanup(lambda: iam.delete_role(RoleName=role_name))

    before = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    assert before["Statement"][0]["Principal"]["Service"] == "ec2.amazonaws.com", (
        f"expected the just-created trust document to name ec2.amazonaws.com, got {before}"
    )

    # Success path: replace the trust document entirely
    iam.update_assume_role_policy(
        RoleName=role_name, PolicyDocument=json.dumps(_UPDATED_TRUST)
    )
    after = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    assert after["Statement"][0]["Principal"]["Service"] == "lambda.amazonaws.com", (
        f"trust policy did not update, got {after}"
    )

    # Error boundary: malformed JSON policy document -> MalformedPolicyDocumentException
    code, message = _error(
        lambda: iam.update_assume_role_policy(
            RoleName=role_name, PolicyDocument="{not-valid-json"
        )
    )
    assert code == "MalformedPolicyDocument", (
        f"expected MalformedPolicyDocument for invalid JSON, got {code}"
    )
    expected = "This policy contains invalid Json"
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # The document must remain unchanged after the rejected update
    still = iam.get_role(RoleName=role_name)["Role"]["AssumeRolePolicyDocument"]
    assert still["Statement"][0]["Principal"]["Service"] == "lambda.amazonaws.com", (
        f"rejected update must not change the existing trust document, got {still}"
    )


def _error(fn):
    """Call fn(); return its error (Code, Message). An unexpected SUCCESS raises, because an
    emulator ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
