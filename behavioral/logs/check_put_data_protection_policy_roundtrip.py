"""put-data-protection-policy-roundtrip."""
from __future__ import annotations

import json

from behavioral_harness import tags


CHECK = "put-data-protection-policy-roundtrip"
GROUP = 'data-protection'
SERVICES = ['logs']


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutDataProtectionPolicy roundtrips via GetDataProtectionPolicy;
    after DeleteDataProtectionPolicy, Get still answers 200 but no longer
    returns this group's policy document."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-dpp-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))

    policy_doc = json.dumps(
        {
            "Name": group,
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
    svc.put_data_protection_policy(logGroupIdentifier=group, policyDocument=policy_doc)

    got = svc.get_data_protection_policy(logGroupIdentifier=group)
    assert got["logGroupIdentifier"] == group, (
        f"expected logGroupIdentifier {group!r}, got {got.get('logGroupIdentifier')!r}"
    )
    got_name = json.loads(got["policyDocument"])["Name"]
    assert got_name == group, f"expected roundtripped policy Name {group!r}, got {got_name!r}"

    svc.delete_data_protection_policy(logGroupIdentifier=group)
    # Real AWS answers Get on a group whose policy was deleted with 200, not 404. A read may
    # fall back to an account-level data protection policy (if one exists in this account), so
    # the proof of the delete is that the document is no longer OUR group-specific policy.
    got_after = svc.get_data_protection_policy(logGroupIdentifier=group)
    assert "policyDocument" not in got_after or json.loads(
        got_after["policyDocument"]
    ).get("Name") != group, (
        f"our deleted group-specific policy is still being returned: {got_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
