"""put-index-policy-then-describe."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


CHECK = "put-index-policy-then-describe"
GROUP = 'index-policies'
SERVICES = ['logs']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIndexPolicy creates a field index policy visible via
    DescribeIndexPolicies and removable via DeleteIndexPolicy."""
    svc = ctx.client("logs")
    group = ctx.unique_name("sim2real-behav-lg-idxpol-")
    svc.create_log_group(logGroupName=group, tags={"Sim2RealOwner": "behavioral-suite"})
    ctx.on_cleanup(lambda _n=group: svc.delete_log_group(logGroupName=_n))
    ctx.on_cleanup(lambda _n=group: svc.put_log_group_deletion_protection(logGroupIdentifier=_n, deletionProtectionEnabled=False))

    policy_doc = json.dumps({"Fields": ["requestId"]})
    svc.put_index_policy(logGroupIdentifier=group, policyDocument=policy_doc)

    desc = svc.describe_index_policies(logGroupIdentifiers=[group])
    policies = desc.get("indexPolicies", [])
    assert len(policies) == 1, f"expected exactly 1 index policy, got {policies!r}"
    assert "requestId" in policies[0]["policyDocument"], (
        f"expected policyDocument to contain 'requestId', got {policies[0]['policyDocument']!r}"
    )

    svc.delete_index_policy(logGroupIdentifier=group)
    desc_after = svc.describe_index_policies(logGroupIdentifiers=[group])
    assert desc_after.get("indexPolicies", []) == [], "index policy still present after delete"

    # Embedded overly-permissive assertion: deleting it again must 404 (no
    # index policy left on this log group to remove).
    code, message = _client_error(lambda: svc.delete_index_policy(logGroupIdentifier=group))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code!r}"
    assert message == "Specified resource does not exist!", f"unexpected message: {message!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
