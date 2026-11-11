"""put-account-policy-then-describe."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _error(fn):
    """Call fn(); return its (error code, error message); an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


def _ignore_not_found(fn):
    """Teardown wrapper: the check deletes this resource itself, so a teardown that finds it
    already gone is the expected outcome, not a leak."""
    try:
        fn()
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


CHECK = "put-account-policy-then-describe"
GROUP = 'account-policy'
SERVICES = ['logs']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:logs-account-policy")
def run(ctx) -> None:
    """PutAccountPolicy creates an account-level policy visible via
    DescribeAccountPolicies and removable via DeleteAccountPolicy."""
    svc = ctx.client("logs")
    policy_name = ctx.unique_name("sim2real-behav-acctpol-")
    policy_type = "DATA_PROTECTION_POLICY"
    policy_doc = json.dumps(
        {
            "Name": policy_name,
            "Version": "2021-06-01",
            "Statement": [
                {
                    "Sid": "audit",
                    "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                    "Operation": {"Audit": {"FindingsDestination": {}}},
                },
                {
                    "Sid": "redact",
                    "DataIdentifier": ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"],
                    "Operation": {"Deidentify": {"MaskConfig": {}}},
                },
            ],
        }
    )
    svc.put_account_policy(policyName=policy_name, policyDocument=policy_doc, policyType=policy_type)
    ctx.on_cleanup(
        lambda _n=policy_name, _t=policy_type: _ignore_not_found(
            lambda: svc.delete_account_policy(policyName=_n, policyType=_t)
        )
    )

    desc = svc.describe_account_policies(policyType=policy_type, policyName=policy_name)
    policies = desc.get("accountPolicies", [])
    assert len(policies) == 1 and policies[0]["policyName"] == policy_name, (
        f"expected exactly 1 account policy named {policy_name!r}, got {policies!r}"
    )

    svc.delete_account_policy(policyName=policy_name, policyType=policy_type)
    remaining_after_delete = svc.describe_account_policies(
        policyType=policy_type, policyName=policy_name
    ).get("accountPolicies", [])
    assert remaining_after_delete == [], (
        f"expected no account policy named {policy_name!r} after delete, "
        f"got {remaining_after_delete!r}"
    )

    # Deleting the same policy again must 404, not silently succeed a second time.
    code, msg = _error(
        lambda: svc.delete_account_policy(policyName=policy_name, policyType=policy_type)
    )
    assert code == "ResourceNotFoundException", f"got {code!r}"
    assert msg == "Specified resource does not exists!", f"got {msg!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
