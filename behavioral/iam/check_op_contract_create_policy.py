"""op-contract-create-policy."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "op-contract-create-policy"
GROUP = "error-semantics"
SERVICES = ["iam"]

_VALID_DOCUMENT = json.dumps(
    {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}],
    }
)


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreatePolicy: success-path creates version v1 as the default version; error
    boundary is MalformedPolicyDocumentException for syntactically invalid JSON, and the
    rejected policy must not be persisted under its own name."""
    iam = ctx.client("iam")

    policy_name = ctx.unique_name("sim2real-policy-")
    created = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=_VALID_DOCUMENT,
        Tags=[{"Key": "sim2real", "Value": "op-contract-create-policy"}],
    )["Policy"]
    policy_arn = created["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))

    assert created["PolicyName"] == policy_name, f"expected PolicyName {policy_name!r}, got {created['PolicyName']!r}"
    assert created["DefaultVersionId"] == "v1", f"expected DefaultVersionId 'v1', got {created['DefaultVersionId']!r}"
    assert policy_arn.endswith(f":policy/{policy_name}"), f"unexpected policy ARN shape: {policy_arn!r}"

    fetched = iam.get_policy(PolicyArn=policy_arn)["Policy"]
    assert fetched["DefaultVersionId"] == "v1", f"expected DefaultVersionId 'v1' on read-back, got {fetched['DefaultVersionId']!r}"

    bad_name = ctx.unique_name("sim2real-bad-policy-")
    code, message = _error(
        lambda: iam.create_policy(PolicyName=bad_name, PolicyDocument="{not valid json"),
        on_success=lambda result: ctx.on_cleanup(
            lambda: iam.delete_policy(PolicyArn=result["Policy"]["Arn"])
        ),
    )
    assert code == "MalformedPolicyDocument", f"expected MalformedPolicyDocument, got {code}"
    assert message == "Syntax errors in policy.", f"expected message 'Syntax errors in policy.', got {message!r}"

    bad_arn = policy_arn.rsplit(":policy/", 1)[0] + f":policy/{bad_name}"
    not_found, not_found_message = _error(
        lambda: iam.get_policy(PolicyArn=bad_arn),
        on_success=lambda result: ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=bad_arn)),
    )
    assert not_found == "NoSuchEntity", (
        f"malformed CreatePolicy must not persist a policy under {bad_name!r}: expected NoSuchEntity, got {not_found}"
    )
    expected = f"Policy {bad_arn} was not found."
    assert not_found_message == expected, f"expected message {expected!r}, got {not_found_message!r}"


def _error(fn, *, on_success=None):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises rather than
    returning a falsy sentinel."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    if on_success is not None:
        on_success(result)
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
