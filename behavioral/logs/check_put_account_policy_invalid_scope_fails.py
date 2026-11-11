"""put-account-policy-invalid-scope-fails."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "put-account-policy-invalid-scope-fails"
GROUP = "error-semantics"
SERVICES = ["logs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-account-policy")
def run(ctx) -> None:
    """PutAccountPolicy with an invalid scope raises InvalidParameterException and stores
    nothing, while the identical call with scope "ALL" succeeds, so the rejection is
    attributable to the scope value."""
    logs = ctx.client("logs")
    policy_name = ctx.unique_name("sim2real-behav-acctpol-")

    # DATA_PROTECTION_POLICY is a true account-wide singleton: at most one may exist,
    # regardless of name. Capture whatever is already there, free it, and register its
    # restoration first so it runs after this check's own cleanup (reverse order).
    displaced = _describe_existing(logs)
    for pol in displaced:
        _safe_delete(logs, pol["policyName"])
    ctx.on_cleanup(lambda: _restore(logs, displaced))

    control_name = ctx.unique_name("sim2real-behav-acctpolctl-")
    ctx.on_cleanup(lambda: _safe_delete(logs, control_name))

    # Positive control: the identical shape of call, with the one valid scope value.
    logs.put_account_policy(
        policyName=control_name,
        policyDocument=_dp_policy_document("sim2realBehavAuditControl"),
        policyType="DATA_PROTECTION_POLICY",
        scope="ALL",
    )
    controlled = logs.describe_account_policies(policyType="DATA_PROTECTION_POLICY")["accountPolicies"]
    assert any(p["policyName"] == control_name for p in controlled), (
        "positive control: PutAccountPolicy with a valid scope did not take effect"
    )

    # Free the slot again before the negative call, so the rejection below cannot be
    # entangled with the one-policy-per-account limit.
    _safe_delete(logs, control_name)
    after_control_delete = logs.describe_account_policies(policyType="DATA_PROTECTION_POLICY")["accountPolicies"]
    assert not any(p["policyName"] == control_name for p in after_control_delete), (
        "positive control policy was not actually deleted before the negative call"
    )

    # Break exactly one thing relative to the positive control: an invalid `scope`.
    code, msg = _error(
        lambda: logs.put_account_policy(
            policyName=policy_name,
            policyDocument=_dp_policy_document("sim2realBehavAudit"),
            policyType="DATA_PROTECTION_POLICY",
            scope="NOT_A_REAL_SCOPE",
        )
    )
    assert code == "InvalidParameterException", f"got {code!r}"
    assert msg == (
        "1 validation error detected: Value at 'scope' failed to satisfy constraint: "
        "Member must satisfy enum value set: [ALL]"
    ), f"got {msg!r}"

    # The rejected call must not have left behind a partially-stored policy.
    existing = logs.describe_account_policies(policyType="DATA_PROTECTION_POLICY")["accountPolicies"]
    assert not any(p["policyName"] == policy_name for p in existing), (
        "PutAccountPolicy stored a policy despite rejecting the request"
    )


# ===== helpers =====
def _dp_policy_document(name: str) -> str:
    identifiers = ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"]
    return json.dumps(
        {
            "Name": name,
            "Version": "2021-06-01",
            "Statement": [
                {
                    "Sid": "audit-policy",
                    "DataIdentifier": identifiers,
                    "Operation": {"Audit": {"FindingsDestination": {}}},
                },
                {
                    "Sid": "redact-policy",
                    "DataIdentifier": identifiers,
                    "Operation": {"Deidentify": {"MaskConfig": {}}},
                },
            ],
        }
    )


def _describe_existing(logs) -> list[dict]:
    """The account's current DATA_PROTECTION_POLICY account policies, verbatim, so they
    can be put back. Empty when there are none (or the read is refused)."""
    try:
        return list(
            logs.describe_account_policies(policyType="DATA_PROTECTION_POLICY").get("accountPolicies", [])
        )
    except Exception:
        return []


def _safe_delete(logs, policy_name: str) -> None:
    try:
        logs.delete_account_policy(policyName=policy_name, policyType="DATA_PROTECTION_POLICY")
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is None or response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise


def _restore(logs, displaced: list[dict]) -> None:
    """Put back every DATA_PROTECTION_POLICY this run displaced, with its original
    name, document and scope."""
    for pol in displaced:
        kwargs = {
            "policyName": pol["policyName"],
            "policyDocument": pol["policyDocument"],
            "policyType": "DATA_PROTECTION_POLICY",
        }
        if pol.get("scope"):
            kwargs["scope"] = pol["scope"]
        logs.put_account_policy(**kwargs)


def _error(fn):
    """Call fn(); return its (error code, error message); an unexpected success raises."""
    try:
        result = fn()
    except Exception as exc:  # botocore.exceptions.ClientError
        response = getattr(exc, "response", None)
        if response is not None:
            err = response.get("Error", {})
            return err.get("Code"), err.get("Message")
        raise
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
