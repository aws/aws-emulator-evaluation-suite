"""put-resource-policy-malformed-json-rejected."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-resource-policy-malformed-json-rejected"
GROUP = "overly-permissive"
SERVICES = ["secretsmanager"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutResourcePolicy rejects a syntactically malformed policy document rather than
    silently storing it, leaves the secret without any attached resource policy, and a
    subsequent well-formed policy on the same secret is still accepted and persisted.
    """
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-badpolicy-")
    secret = sm.create_secret(
        Name=name,
        SecretString="policy-target-value",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )
    arn = secret["ARN"]
    ctx.on_cleanup(lambda: sm.delete_secret(SecretId=arn, ForceDeleteWithoutRecovery=True))

    malformed = '{"Version": "2012-10-17", "Statement": [ { "Effect": "Allow", '  # truncated / invalid JSON
    code, message = _error_code(lambda: sm.put_resource_policy(SecretId=arn, ResourcePolicy=malformed))
    assert code == "MalformedPolicyDocumentException", f"expected MalformedPolicyDocumentException, got {code}"
    assert message == "This resource policy contains a syntax error.", f"unexpected refusal message: {message!r}"

    # Effect absent: the rejected call did not store anything.
    resp = sm.get_resource_policy(SecretId=arn)
    assert resp.get("ResourcePolicy") is None, "malformed policy call unexpectedly persisted a policy"

    # Positive control: a syntactically valid policy on the same secret is accepted and readable back.
    account_id = ctx.client("sts").get_caller_identity()["Account"]
    valid_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Effect": "Allow",
                "Principal": {"AWS": f"arn:aws:iam::{account_id}:root"},
                "Action": "secretsmanager:GetSecretValue",
                "Resource": "*",
            }
        ],
    }
    sm.put_resource_policy(SecretId=arn, ResourcePolicy=json.dumps(valid_policy))
    stored = sm.get_resource_policy(SecretId=arn)
    assert stored.get("ResourcePolicy") is not None
    assert "GetSecretValue" in stored["ResourcePolicy"]


def _error_code(fn):
    """Call fn(); return its botocore (Error code, Error message). An unexpected SUCCESS raises, because
    an emulator accepting input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as err:
        return err.response["Error"]["Code"], err.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
