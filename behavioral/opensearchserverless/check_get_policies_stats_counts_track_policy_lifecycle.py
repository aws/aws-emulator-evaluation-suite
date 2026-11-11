"""get-policies-stats-counts-track-policy-lifecycle."""
from __future__ import annotations

import json
from typing import Any, Callable

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "get-policies-stats-counts-track-policy-lifecycle"
GROUP = "server-side"
SERVICES = ["opensearchserverless"]

# AWS behaviors this check relies on:
#   1. THE RESPONSE SHAPE. The model (opensearchserverless-2021-11-01.json) declares, unusually for
#      this API, PascalCase members:
#        AccessPolicyStats.DataPolicyCount, SecurityPolicyStats.EncryptionPolicyCount,
#        SecurityPolicyStats.NetworkPolicyCount, LifecyclePolicyStats.RetentionPolicyCount,
#        SecurityConfigStats.SamlConfigCount, TotalPolicyCount (all smithy.api#Long).
#      Only that spelling is accepted: accepting both is how a representation check stops
#      discriminating.
#   2. EVERY BUCKET IS PRESENT even when its count is 0, so each bucket is hard-subscripted.
#   3. `TotalPolicyCount` IS THE SUM OF THE FOUR TYPED BUCKETS. The model's own wording is "the total
#      number of OpenSearch Serverless security policies AND CONFIGURATIONS in your account", which
#      is why SamlConfigCount is included in the sum.
#   4. THE DELTAS ARE EXACTLY +1 / -1 on the read after CreateSecurityPolicy / DeleteSecurityPolicy.
#   5. ACCOUNT-GLOBAL STATE. GetPoliciesStats reads ACCOUNT-WIDE state, so a concurrent writer of any
#      policy breaks the exact deltas. The assertion stays EXACT rather than `>=`, because `>=` would
#      pass against a target that never decrements.

# ===== helpers =====


def _aoss_name(ctx, prefix: str, maxlen: int = 32) -> str:
    """A name matching aoss's ``^[a-z][a-z0-9-]+$`` within ``maxlen`` (policy names cap at 32)."""
    raw = ctx.unique_name(prefix).lower()
    kept = "".join(ch if (ch.isalpha() and ch.isascii()) or ch.isdigit() or ch == "-" else "-"
                   for ch in raw)
    while "--" in kept:
        kept = kept.replace("--", "-")
    kept = kept.strip("-")
    if not kept or not kept[0].isalpha():
        kept = "a" + kept
    return kept[:maxlen].rstrip("-")


def _error(fn: Callable[[], Any]) -> tuple[str, str]:
    """(code, message) of the error ``fn`` raises. An unexpected success raises AssertionError, so a
    target that accepts what AWS refuses fails loudly instead of reading as a code mismatch."""
    try:
        result = fn()
    except Exception as exc:
        response = getattr(exc, "response", None)
        if response is None:
            raise
        return response["Error"]["Code"], response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded and returned {result!r}")


def _buckets(ctx) -> dict[str, int]:
    """Every count GetPoliciesStats reports, flattened. Hard-subscripted: a missing bucket must fail
    loudly rather than be defaulted into agreeing with whatever the check expects."""
    stats = ctx.client("opensearchserverless").get_policies_stats()
    for holder in ("AccessPolicyStats", "SecurityPolicyStats", "LifecyclePolicyStats",
                   "SecurityConfigStats"):
        assert holder in stats, (
            f"expected GetPoliciesStats to report {holder!r}; got keys {sorted(stats)!r}"
        )
    assert "TotalPolicyCount" in stats, (
        f"expected GetPoliciesStats to report TotalPolicyCount; got keys {sorted(stats)!r}"
    )
    return {
        "data": stats["AccessPolicyStats"]["DataPolicyCount"],
        "encryption": stats["SecurityPolicyStats"]["EncryptionPolicyCount"],
        "network": stats["SecurityPolicyStats"]["NetworkPolicyCount"],
        "retention": stats["LifecyclePolicyStats"]["RetentionPolicyCount"],
        "saml": stats["SecurityConfigStats"]["SamlConfigCount"],
        "total": stats["TotalPolicyCount"],
    }


def _assert_only_bucket_moved(before: dict[str, int], after: dict[str, int], bucket: str,
                              delta: int, what: str) -> None:
    """Every typed bucket other than ``bucket`` must be UNCHANGED, and ``bucket`` and ``total`` must
    each have moved by exactly ``delta``. Cross-bucket isolation is what makes this more than a
    counter: a target with one global counter fails it."""
    typed = ("data", "encryption", "network", "retention", "saml")
    for name in typed:
        expected = before[name] + (delta if name == bucket else 0)
        assert after[name] == expected, (
            f"after {what}, expected the {name!r} count to be {expected} (baseline {before[name]}, "
            f"delta {delta if name == bucket else 0}), got {after[name]}; full baseline {before!r} "
            f"vs {after!r}"
        )
    assert after["total"] == before["total"] + delta, (
        f"after {what}, expected TotalPolicyCount to be {before['total'] + delta} (baseline "
        f"{before['total']}, delta {delta}), got {after['total']}"
    )


def _delete_security_policy(ctx, policy_type: str, name: str) -> None:
    osc = ctx.client("opensearchserverless")
    try:
        osc.delete_security_policy(type=policy_type, name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


# ===== end helpers =====


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """``GetPoliciesStats`` is a live projection over the account's policy store: one ENCRYPTION policy
    moves EncryptionPolicyCount and TotalPolicyCount by exactly +1 (no other bucket) and back by -1 on
    delete, TotalPolicyCount equals the sum of the typed buckets, and unmutated reads agree exactly.
    """
    osc = ctx.client("opensearchserverless")

    # --- BASELINE, from the account itself. Nothing here is a literal.
    baseline = _buckets(ctx)
    for name, value in baseline.items():
        assert isinstance(value, int) and value >= 0, (
            f"expected the {name!r} count to be a non-negative integer, got {value!r}"
        )
    typed_sum = sum(baseline[k] for k in ("data", "encryption", "network", "retention", "saml"))
    assert baseline["total"] == typed_sum, (
        f"expected TotalPolicyCount to equal the sum of the typed buckets ({typed_sum}), got "
        f"{baseline['total']}; buckets were {baseline!r}"
    )

    # --- FREEZE DETECTOR: a read must not advance the counts.
    repeats = [_buckets(ctx) for _ in range(3)]
    assert repeats[0] == repeats[1] == repeats[2] == baseline, (
        f"expected three consecutive GetPoliciesStats reads with no mutation between them to return "
        f"the identical counts, got {baseline!r} then {repeats!r}"
    )

    # --- ONE ENCRYPTION POLICY.
    enc_name = _aoss_name(ctx, "sim2real-aoss-stats-enc-")
    subject = _aoss_name(ctx, "sim2real-aoss-stats-", maxlen=64)
    osc.create_security_policy(
        type="encryption",
        name=enc_name,
        policy=json.dumps({
            "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{subject}"]}],
            "AWSOwnedKey": True,
        }),
    )
    ctx.on_cleanup(lambda: _delete_security_policy(ctx, "encryption", enc_name))

    after_create = _buckets(ctx)
    _assert_only_bucket_moved(
        baseline, after_create, "encryption", +1, "creating one encryption security policy",
    )

    # --- ONE NETWORK POLICY, to prove the two SecurityPolicyStats buckets are counted separately
    # rather than being one number reported twice.
    net_name = _aoss_name(ctx, "sim2real-aoss-stats-net-")
    osc.create_security_policy(
        type="network",
        name=net_name,
        policy=json.dumps([
            {
                "Rules": [{"ResourceType": "collection", "Resource": [f"collection/{subject}"]}],
                "AllowFromPublic": False,
                "SourceServices": ["bedrock.amazonaws.com"],
            }
        ]),
    )
    ctx.on_cleanup(lambda: _delete_security_policy(ctx, "network", net_name))

    after_network = _buckets(ctx)
    _assert_only_bucket_moved(
        after_create, after_network, "network", +1, "creating one network security policy",
    )

    # --- DELETE, and the count must come back down. This is the beat a target that only ever
    # increments cannot make.
    osc.delete_security_policy(type="network", name=net_name)
    after_network_delete = _buckets(ctx)
    _assert_only_bucket_moved(
        after_network, after_network_delete, "network", -1, "deleting that network security policy",
    )
    assert after_network_delete == after_create, (
        f"expected the counts after create+delete of one network policy to be identical to the "
        f"counts before it ({after_create!r}), got {after_network_delete!r}"
    )

    # --- The deleted policy is gone by an independent read, and a MUTATION on the dead name also
    # fails with the specific not-found code, while the encryption policy created in the same run is
    # still readable (so "not found" is not this target's answer to everything).
    code, message = _error(lambda: osc.get_security_policy(type="network", name=net_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException reading the deleted network policy {net_name!r}, got "
        f"{code!r}"
    )
    expected_message = f"Policy with name {net_name} and type network is not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    code, message = _error(lambda: osc.delete_security_policy(type="network", name=net_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting the already-deleted network policy "
        f"{net_name!r}, got {code!r}"
    )
    expected_message = f"Policy with name {net_name} and type network is not found"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"
    surviving = osc.get_security_policy(type="encryption", name=enc_name)["securityPolicyDetail"]
    assert surviving["name"] == enc_name, (
        f"expected the encryption policy {enc_name!r} to survive the network policy's deletion, got "
        f"{surviving!r}"
    )

    # --- And the encryption policy's own deletion brings every bucket back to the account baseline.
    osc.delete_security_policy(type="encryption", name=enc_name)
    final = _buckets(ctx)
    _assert_only_bucket_moved(
        after_network_delete, final, "encryption", -1, "deleting that encryption security policy",
    )
    assert final == baseline, (
        f"expected every GetPoliciesStats bucket to return to the account baseline {baseline!r} "
        f"after this check deleted everything it created, got {final!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
