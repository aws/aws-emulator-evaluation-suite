"""account-policy-limit-exceeded-enforced."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "account-policy-limit-exceeded-enforced"
GROUP = "server-side"
SERVICES = ["logs"]

_POLICY_TYPE = "DATA_PROTECTION_POLICY"


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-account-policy")
def run(ctx) -> None:
    """A second account-level DATA_PROTECTION_POLICY raises LimitExceededException,
    leaves the first policy unaffected, and succeeds once the single slot is freed."""
    logs = ctx.client("logs")

    # The quota is one DATA_PROTECTION_POLICY per account: capture and free the slot,
    # and register its restore first so it runs after this check's own policies are deleted.
    displaced = _describe_existing(logs)
    for pol in displaced:
        _delete_best_effort(logs, pol["policyName"])
    ctx.on_cleanup(lambda: _restore(logs, displaced))

    name1 = ctx.unique_name("sim2real-behav-dplimit1-")
    logs.put_account_policy(
        policyName=name1, policyDocument=json.dumps(_dp_policy_doc("limit-test-1")), policyType=_POLICY_TYPE
    )
    ctx.on_cleanup(lambda: _delete_best_effort(logs, name1))

    described = logs.describe_account_policies(policyType=_POLICY_TYPE, policyName=name1)
    assert len(described["accountPolicies"]) == 1

    name2 = ctx.unique_name("sim2real-behav-dplimit2-")
    code, message = _error(
        lambda: logs.put_account_policy(
            policyName=name2, policyDocument=json.dumps(_dp_policy_doc("limit-test-2")), policyType=_POLICY_TYPE
        )
    )
    assert code == "LimitExceededException", (
        f"expected LimitExceededException creating a second account-level data protection policy, got {code!r}"
    )
    expected_message = "Resource limit exceeded."
    assert message == expected_message, (
        f"expected the exact message {expected_message!r}, got {message!r}"
    )

    # The first policy must remain untouched by the rejected second attempt.
    still_there = logs.describe_account_policies(policyType=_POLICY_TYPE, policyName=name1)
    assert len(still_there["accountPolicies"]) == 1
    assert json.loads(still_there["accountPolicies"][0]["policyDocument"])["Name"] == "limit-test-1"

    # Restore leg: free the single account-wide slot and prove the *identical* call
    # that was just rejected now succeeds. Without this, the LimitExceededException
    # above could not be distinguished from a server-side bug in the second call's
    # shape that happens to share an error code with the real quota.
    logs.delete_account_policy(policyName=name1, policyType=_POLICY_TYPE)
    emptied = logs.describe_account_policies(policyType=_POLICY_TYPE)
    assert emptied["accountPolicies"] == [], f"expected the slot to be free, still saw {emptied['accountPolicies']!r}"

    logs.put_account_policy(
        policyName=name2, policyDocument=json.dumps(_dp_policy_doc("limit-test-2")), policyType=_POLICY_TYPE
    )
    ctx.on_cleanup(lambda: _delete_best_effort(logs, name2))
    recovered = logs.describe_account_policies(policyType=_POLICY_TYPE, policyName=name2)
    assert len(recovered["accountPolicies"]) == 1, (
        f"expected the previously-rejected policy to succeed once the slot is free, got {recovered!r}"
    )


# ===== helpers =====
def _dp_policy_doc(name: str) -> dict:
    identifiers = ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"]
    return {
        "Name": name,
        "Version": "2021-06-01",
        "Statement": [
            {"Sid": "audit", "DataIdentifier": identifiers, "Operation": {"Audit": {"FindingsDestination": {}}}},
            {"Sid": "redact", "DataIdentifier": identifiers, "Operation": {"Deidentify": {"MaskConfig": {}}}},
        ],
    }


def _describe_existing(logs) -> list[dict]:
    """The account-level policies of `_POLICY_TYPE` currently installed, verbatim, so they
    can be put back. Returns [] when there are none (or the read is refused)."""
    try:
        return list(logs.describe_account_policies(policyType=_POLICY_TYPE).get("accountPolicies", []))
    except ClientError:
        return []


def _restore(logs, displaced: list[dict]) -> None:
    """Put back every policy `run` displaced, with its original name, document and scope."""
    for pol in displaced:
        kwargs = {
            "policyName": pol["policyName"],
            "policyDocument": pol["policyDocument"],
            "policyType": _POLICY_TYPE,
        }
        for optional in ("scope", "selectionCriteria"):
            if pol.get(optional):
                kwargs[optional] = pol[optional]
        logs.put_account_policy(**kwargs)


def _delete_best_effort(logs, policy_name: str) -> None:
    try:
        logs.delete_account_policy(policyName=policy_name, policyType=_POLICY_TYPE)
    except ClientError as err:
        if err.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _error(fn):
    """Call fn() expecting a ClientError; return its (Code, Message). A success raises, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except ClientError as err:
        error = err.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
