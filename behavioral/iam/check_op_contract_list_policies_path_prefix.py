"""op-contract-listPolicies-path-prefix."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listPolicies-path-prefix"
GROUP = "error-semantics"
SERVICES = ["iam"]

_POLICY_DOC = json.dumps(
    {"Version": "2012-10-17", "Statement": [{"Effect": "Deny", "Action": "s3:DeleteBucket", "Resource": "*"}]}
)


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PathPrefix + Scope=Local returns exactly the customer managed policy the check created; an
    invalid Scope value is rejected by the service with the exact ValidationError message."""
    iam = ctx.client("iam")
    suffix = ctx.unique_name("sim2real-batch09-pol")
    path = f"/{suffix}/"
    policy_name = f"{suffix}-policy"
    policy_arn = iam.create_policy(
        PolicyName=policy_name,
        PolicyDocument=_POLICY_DOC,
        Path=path,
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=policy_arn))

    resp = iam.list_policies(Scope="Local", PathPrefix=path)
    policies = resp["Policies"]
    assert len(policies) == 1, f"expected exactly 1 policy under {path}, got {policies}"
    assert policies[0]["PolicyName"] == policy_name, f"expected PolicyName {policy_name}, got {policies[0]['PolicyName']}"
    assert policies[0]["Arn"] == policy_arn, f"expected Arn {policy_arn}, got {policies[0]['Arn']}"
    assert policies[0]["AttachmentCount"] == 0, f"expected AttachmentCount 0, got {policies[0]['AttachmentCount']}"

    # Error boundary: Scope has a closed enum (All/AWS/Local) but botocore does not validate enum
    # members client-side, so an invalid value is sent over the wire and rejected by IAM itself.
    try:
        iam.list_policies(Scope="Bogus")
        raise AssertionError("expected ValidationError for Scope=Bogus")
    except ClientError as exc:
        error = exc.response["Error"]
    assert error["Code"] == "ValidationError", f"expected ValidationError, got {error['Code']}"
    expected = (
        "1 validation error detected: Value at 'scope' failed to satisfy constraint: "
        "Member must satisfy enum value set: [All, Local, AWS]"
    )
    assert error.get("Message") == expected, f"expected message {expected!r}, got {error.get('Message')!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
