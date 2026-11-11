"""account-policy-enforced-globally-without-per-group-config."""
from __future__ import annotations

import json

from behavioral_harness import tags

CHECK = "account-policy-enforced-globally-without-per-group-config"
GROUP = "server-side"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:logs-account-policy")
def run(ctx) -> None:
    """An account-level field index policy (PutAccountPolicy) is enforced on a brand-new log
    group that has no log-group-level index policy of its own, as reported by
    DescribeIndexPolicies (which flattens account-level defaults into the per-group view)."""
    logs = ctx.client("logs")

    policy_name = ctx.unique_name("sim2real-behav-acctidx-")
    policy_document = {"Fields": ["OrderId"]}
    # Real CloudWatch Logs rejects an explicit scope="ALL_LOG_GROUPS" for
    # FIELD_INDEX_POLICY with InvalidParameterException -- ALL_LOG_GROUPS is only the
    # implicit default when the parameter is omitted entirely, so leave it unset here.
    logs.put_account_policy(
        policyName=policy_name,
        policyDocument=json.dumps(policy_document),
        policyType="FIELD_INDEX_POLICY",
    )
    ctx.on_cleanup(
        lambda: logs.delete_account_policy(policyName=policy_name, policyType="FIELD_INDEX_POLICY")
    )

    acct_policies = logs.describe_account_policies(policyType="FIELD_INDEX_POLICY")[
        "accountPolicies"
    ]
    matches = [p for p in acct_policies if p["policyName"] == policy_name]
    assert matches, f"account policy {policy_name} missing from DescribeAccountPolicies"
    assert json.loads(matches[0]["policyDocument"]) == policy_document, (
        f"expected account policy document {policy_document}, got "
        f"{json.loads(matches[0]['policyDocument'])}"
    )

    log_group = ctx.unique_name("sim2real-behav-noindexoverride-")
    logs.create_log_group(logGroupName=log_group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda: logs.delete_log_group(logGroupName=log_group))

    # No PutIndexPolicy call was ever made for this specific log group.
    described = logs.describe_index_policies(logGroupIdentifiers=[log_group])
    index_policies = described["indexPolicies"]
    assert index_policies, (
        "DescribeIndexPolicies returned no policy for a log group with no per-group override, "
        "even though an account-wide FIELD_INDEX_POLICY applies to all log groups"
    )
    effective = index_policies[0]
    assert effective["policyName"] == policy_name, (
        f"expected the effective policy to be the account-level policy {policy_name}, "
        f"got {effective['policyName']}"
    )
    assert "ACCOUNT" in effective["source"].upper(), (
        f"expected source to indicate the policy came from the account level, got "
        f"{effective['source']}"
    )
    assert json.loads(effective["policyDocument"]) == policy_document, (
        f"expected the effective policy document to equal the account-level policy "
        f"{policy_document}, got {json.loads(effective['policyDocument'])}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
