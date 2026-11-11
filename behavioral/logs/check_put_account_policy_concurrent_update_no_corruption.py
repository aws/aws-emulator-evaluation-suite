"""put-account-policy-concurrent-update-no-corruption."""
from __future__ import annotations

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-account-policy-concurrent-update-no-corruption"
GROUP = "concurrency"
SERVICES = ["logs"]

_POLICY_TYPE = "DATA_PROTECTION_POLICY"


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:logs-account-policy")
def run(ctx) -> None:
    """Concurrent PutAccountPolicy calls for one name/type converge to a single uncorrupted
    document; DeleteAccountPolicy removes it and a second delete is rejected."""
    logs = ctx.client("logs")

    # Best-effort: an account can have only one DATA_PROTECTION_POLICY account
    # policy, so clear any leftover one before starting.
    _clear_existing_account_policies(logs)

    policy_name = ctx.unique_name("sim2real-behav-acctdp-")
    ctx.on_cleanup(lambda: _delete_best_effort(logs, policy_name))

    doc_a = _dp_policy_doc("variant-a")
    doc_b = _dp_policy_doc("variant-b")

    def _put(doc):
        return logs.put_account_policy(
            policyName=policy_name, policyDocument=json.dumps(doc), policyType=_POLICY_TYPE
        )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = [pool.submit(_put, doc_a), pool.submit(_put, doc_b)]
        for fut in futures:
            fut.result()  # both concurrent writers must succeed (update-in-place, no conflict)

    described = _poll_until(
        lambda: logs.describe_account_policies(policyType=_POLICY_TYPE, policyName=policy_name),
        lambda r: len(r.get("accountPolicies", [])) == 1,
        timeout_s=30.0,
        interval_s=1.5,
    )
    policies = described["accountPolicies"]
    assert len(policies) == 1, f"expected exactly one converged account policy, got {len(policies)}"

    stored_doc = json.loads(policies[0]["policyDocument"])
    assert stored_doc["Name"] in ("variant-a", "variant-b"), (
        f"final policy document is neither submitted variant (corrupted?): {stored_doc}"
    )
    # The document must be internally consistent (matches exactly one submitted variant,
    # not an interleaved/merged mix of both).
    expected = doc_a if stored_doc["Name"] == "variant-a" else doc_b
    assert stored_doc == expected, f"final policy document does not match either submitted variant cleanly: {stored_doc}"

    # The teardown already deletes this policy; make that delete provable instead of unasserted:
    # deleting it here proves gone (independent read) and that a further delete on the now-dead
    # name is rejected, not silently accepted.
    logs.delete_account_policy(policyName=policy_name, policyType=_POLICY_TYPE)
    code, msg = _error(
        lambda: logs.delete_account_policy(policyName=policy_name, policyType=_POLICY_TYPE)
    )
    assert code == "ResourceNotFoundException", (
        f"deleting an already-deleted account policy must fail with ResourceNotFoundException, "
        f"got {code!r}"
    )
    assert msg == "Specified resource does not exists!", f"got {msg!r}"

    gone = _poll_until(
        lambda: logs.describe_account_policies(policyType=_POLICY_TYPE, policyName=policy_name),
        lambda r: len(r.get("accountPolicies", [])) == 0,
        timeout_s=30.0,
        interval_s=1.5,
    )
    assert gone.get("accountPolicies", []) == [], f"deleted account policy must not still be listed: {gone}"


# ===== helpers =====
def _error(fn):
    """Call fn(); return its (error code, error message). An unexpected SUCCESS raises,
    because an emulator ACCEPTING a call real AWS refuses must not read as a mere mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _dp_policy_doc(name: str) -> dict:
    identifiers = ["arn:aws:dataprotection::aws:data-identifier/EmailAddress"]
    return {
        "Name": name,
        "Version": "2021-06-01",
        "Statement": [
            {
                "Sid": "audit",
                "DataIdentifier": identifiers,
                "Operation": {"Audit": {"FindingsDestination": {}}},
            },
            {
                "Sid": "redact",
                "DataIdentifier": identifiers,
                "Operation": {"Deidentify": {"MaskConfig": {}}},
            },
        ],
    }


def _clear_existing_account_policies(logs) -> None:
    try:
        existing = logs.describe_account_policies(policyType=_POLICY_TYPE).get("accountPolicies", [])
    except ClientError:
        return
    for pol in existing:
        _delete_best_effort(logs, pol["policyName"])


def _delete_best_effort(logs, policy_name: str) -> None:
    try:
        logs.delete_account_policy(policyName=policy_name, policyType=_POLICY_TYPE)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float) -> Any:
    deadline = time.monotonic() + timeout_s
    result = probe()
    while not predicate(result):
        if time.monotonic() >= deadline:
            raise AssertionError(f"condition not met within {timeout_s}s; last result={result!r}")
        time.sleep(interval_s)
        result = probe()
    return result


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
