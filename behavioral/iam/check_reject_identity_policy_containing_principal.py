"""reject-identity-policy-containing-principal."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "reject-identity-policy-containing-principal"
GROUP = 'overly-permissive'
SERVICES = ['iam']


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Identity-based (managed) policies may NOT contain a Principal element -
    that is only legal in resource/trust policies. Accepting it would grant a
    materially different, broader policy than the caller wrote."""
    iam = ctx.client("iam")
    doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "*"},
                    "Action": "s3:GetObject",
                    "Resource": "*",
                }
            ],
        }
    )

    # Positive control: prove CreatePolicy otherwise works on this target
    # before trusting a rejection from it. Without this, a target that
    # rejects every CreatePolicy call would score identically to one that
    # specifically rejects a Principal in an identity policy.
    control_doc = json.dumps(
        {
            "Version": "2012-10-17",
            "Statement": [
                {"Effect": "Allow", "Action": "s3:GetObject", "Resource": "*"}
            ],
        }
    )
    control_name = ctx.unique_name("sim2real-behav-iam-principal-control-")
    control_arn = iam.create_policy(
        PolicyName=control_name, PolicyDocument=control_doc
    )["Policy"]["Arn"]
    ctx.on_cleanup(lambda: iam.delete_policy(PolicyArn=control_arn))
    assert iam.get_policy(PolicyArn=control_arn)["Policy"]["DefaultVersionId"] == "v1", (
        "positive control: a Principal-free identity policy must be creatable "
        "before trusting a rejection of one that has a Principal"
    )

    policy_name = ctx.unique_name("sim2real-behav-iam-principal-policy-")
    # Nothing is expected to be created, but a target that WRONGLY accepts the
    # document would otherwise leak a managed policy into the account.
    ctx.on_cleanup(lambda: _delete_local_policy_by_name(iam, policy_name))

    code, message = _error_code(
        lambda: iam.create_policy(PolicyName=policy_name, PolicyDocument=doc)
    )
    assert code == "MalformedPolicyDocument", (
        f"expected MalformedPolicyDocument for Principal in an identity "
        f"policy, got {code}"
    )
    expected = "Policy document should not specify a principal."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Confirm no policy was persisted despite the rejection.
    names = [
        p["PolicyName"]
        for p in iam.list_policies(Scope="Local").get("Policies", [])
    ]
    assert policy_name not in names, (
        f"rejected policy {policy_name!r} must not appear in ListPolicies, "
        f"got names={names}"
    )


# ===== helpers =====

def _error_code(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises: a target
    accepting what real AWS refuses must not read as a mere code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _delete_local_policy_by_name(iam, policy_name: str) -> None:
    for page in iam.get_paginator("list_policies").paginate(Scope="Local"):
        for policy in page.get("Policies", []):
            if policy["PolicyName"] == policy_name:
                try:
                    iam.delete_policy(PolicyArn=policy["Arn"])
                except ClientError as exc:
                    if exc.response["Error"]["Code"] != "NoSuchEntity":
                        raise
                return


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
