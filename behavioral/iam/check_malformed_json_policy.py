"""malformed-json-policy."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "malformed-json-policy"
GROUP = 'policy_document_validation'
SERVICES = ['iam']

ERR_MALFORMED_POLICY = "MalformedPolicyDocument"

VALID_POLICY = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:ListBucket", "Resource": "*"}],
    }
)

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePolicy with syntactically invalid JSON raises MalformedPolicyDocument and persists
    nothing, against a positive control proving the same call succeeds with valid JSON."""
    iam = ctx.client("iam")

    # Positive control: the identical call, with a syntactically valid document, succeeds.
    good_name = ctx.unique_name("sim2real-behav-pol-good-")
    good_arn = iam.create_policy(PolicyName=good_name, PolicyDocument=VALID_POLICY)["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=good_arn))
    assert iam.get_policy(PolicyArn=good_arn)["Policy"]["PolicyName"] == good_name, (
        f"positive control: a syntactically valid PolicyDocument must create a real, readable policy "
        f"at {good_arn!r}"
    )

    # Break exactly one thing: syntactically invalid JSON in the same field.
    bad_name = ctx.unique_name("sim2real-behav-pol-bad-")
    code, message = _error(
        lambda: iam.create_policy(PolicyName=bad_name, PolicyDocument="not valid json {{{")
    )
    assert code == ERR_MALFORMED_POLICY, f"Expected {ERR_MALFORMED_POLICY}, got {code!r}"
    assert message == "Syntax errors in policy.", (
        f"the malformed document must be refused with AWS's exact message "
        f"'Syntax errors in policy.'; got {message!r}"
    )

    # Effect absent, via an independent read at the destination: no policy was persisted under the
    # name the rejected call would have used.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    bad_arn = f"arn:aws:iam::{account_id}:policy/{bad_name}"
    code_get, message_get = _error(lambda: iam.get_policy(PolicyArn=bad_arn))
    assert code_get == "NoSuchEntity", (
        f"rejected CreatePolicy must not persist a policy: GetPolicy({bad_arn!r}) expected "
        f"NoSuchEntity, got {code_get!r}"
    )
    expected_missing = f"Policy {bad_arn} was not found."
    assert message_get == expected_missing, (
        f"GetPolicy on the never-created ARN must carry AWS's exact message {expected_missing!r}; "
        f"got {message_get!r}"
    )


def _error(fn):
    """``(code, message)`` of a call real AWS refuses; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"real AWS refuses this call, but it succeeded and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
