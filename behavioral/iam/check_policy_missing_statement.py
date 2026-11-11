"""policy-missing-statement."""
from __future__ import annotations

from botocore.exceptions import ClientError

import json

from behavioral_harness import tags

CHECK = "policy-missing-statement"
GROUP = 'policy_document_validation'
SERVICES = ['iam']

ERR_MALFORMED_POLICY = "MalformedPolicyDocument"
ERR_NO_SUCH_ENTITY = "NoSuchEntity"

VALID_DOC = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "iam:GetUser", "Resource": "*"}],
    }
)


def _err_code(fn):
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code"), exc.response.get("Error", {}).get("Message")
    raise AssertionError("expected the call to raise a ClientError, but it succeeded")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePolicy with missing Statement field raises MalformedPolicyDocument and persists
    nothing, while a well-formed policy document on the same account is unaffected."""
    iam = ctx.client("iam")

    # positive control: a well-formed document succeeds on the same wiring.
    control_name = ctx.unique_name("sim2real-behav-pol-ctrl-")
    control_arn = iam.create_policy(PolicyName=control_name, PolicyDocument=VALID_DOC)["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=control_arn))
    got_control = iam.get_policy(PolicyArn=control_arn)["Policy"]
    assert got_control["PolicyName"] == control_name, f"positive control did not persist: {got_control}"

    # negative: missing Statement field
    bad_name = ctx.unique_name("sim2real-behav-pol-")
    bad_doc = json.dumps({"Version": "2012-10-17"})
    code, message = _err_code(lambda: iam.create_policy(PolicyName=bad_name, PolicyDocument=bad_doc))
    assert code == ERR_MALFORMED_POLICY, f"Expected {ERR_MALFORMED_POLICY}, got {code!r}"
    assert message == "Syntax errors in policy.", (
        f"expected the exact MalformedPolicyDocument message AWS returns, got {message!r}"
    )

    # effect absent: the rejected policy never exists at its deterministic ARN, read via an
    # independent operation (GetPolicy, not CreatePolicy's own response).
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bad_arn = f"arn:aws:iam::{account_id}:policy/{bad_name}"
    code_get, message_get = _err_code(lambda: iam.get_policy(PolicyArn=bad_arn))
    assert code_get == ERR_NO_SUCH_ENTITY, (
        f"rejected CreatePolicy must not persist a policy: GetPolicy returned {code_get!r}"
    )
    assert message_get == f"Policy {bad_arn} was not found.", (
        f"expected the exact NoSuchEntity message AWS returns, got {message_get!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
