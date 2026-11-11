"""policy-empty-statement-array."""
from __future__ import annotations

from botocore.exceptions import ClientError

import json

from behavioral_harness import tags

CHECK = "policy-empty-statement-array"
GROUP = 'policy_document_validation'
SERVICES = ['iam']

ERR_MALFORMED_POLICY = "MalformedPolicyDocument"

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreatePolicy with empty Statement array raises MalformedPolicyDocument."""
    iam = ctx.client("iam")

    # Positive control: a well-formed document must succeed on this account/credentials, so
    # the rejection below is attributable to the empty Statement array specifically, not to
    # every CreatePolicy call.
    good_doc = json.dumps(
        {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "iam:GetUser", "Resource": "*"}]}
    )
    good_name = ctx.unique_name("sim2real-behav-pol-ctrl-")
    good_arn = iam.create_policy(PolicyName=good_name, PolicyDocument=good_doc)["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=good_arn))
    control_name = iam.get_policy(PolicyArn=good_arn)["Policy"]["PolicyName"]
    assert control_name == good_name, (
        f"positive control: well-formed CreatePolicy must succeed and be independently readable "
        f"back before the empty-Statement rejection below can be attributed to it; got {control_name!r}"
    )

    bad_doc = json.dumps({"Version": "2012-10-17", "Statement": []})
    try:
        iam.create_policy(PolicyName=ctx.unique_name("sim2real-behav-pol-"), PolicyDocument=bad_doc)
        code = None
        message = None
    except ClientError as exc:
        code = exc.response.get("Error", {}).get("Code")
        message = exc.response.get("Error", {}).get("Message")
    assert code == ERR_MALFORMED_POLICY, f"Expected {ERR_MALFORMED_POLICY}, got {code!r}"
    assert message == "Syntax errors in policy.", (
        f"expected the exact MalformedPolicyDocument message AWS returns, got {message!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
