"""index-policy-lifecycle."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "index-policy-lifecycle"
GROUP = "state-machine"
SERVICES = ["logs"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutIndexPolicy creates a field-index policy visible in DescribeIndexPolicies,
    and DeleteIndexPolicy removes it so DescribeIndexPolicies no longer reports it
    and a second delete against the same log group fails as not-found."""
    logs = ctx.client("logs")
    log_group_name = ctx.unique_name("sim2real-behav-lg-")
    logs.create_log_group(
        logGroupName=log_group_name, tags={"Sim2RealOwner": "behavioral-suite"}
    )
    ctx.on_cleanup(lambda: _ignore_notfound(lambda: logs.delete_log_group(logGroupName=log_group_name)))
    ctx.on_cleanup(
        lambda: _ignore_notfound(lambda: logs.delete_index_policy(logGroupIdentifier=log_group_name))
    )

    policy_document = json.dumps({"Fields": ["RequestId"]})
    logs.put_index_policy(logGroupIdentifier=log_group_name, policyDocument=policy_document)

    policies = logs.describe_index_policies(logGroupIdentifiers=[log_group_name])["indexPolicies"]
    assert len(policies) == 1, f"expected exactly one index policy right after put, got {policies}"
    assert "RequestId" in policies[0]["policyDocument"], f"unexpected policyDocument: {policies[0]}"

    logs.delete_index_policy(logGroupIdentifier=log_group_name)

    policies_after = logs.describe_index_policies(logGroupIdentifiers=[log_group_name])["indexPolicies"]
    assert policies_after == [], f"expected no index policy after delete, got {policies_after}"

    code, message = _error(lambda: logs.delete_index_policy(logGroupIdentifier=log_group_name))
    assert code == "ResourceNotFoundException", (
        f"expected ResourceNotFoundException deleting an already-deleted index policy, got {code!r}"
    )
    expected_message = "Specified resource does not exist!"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return its ClientError code and message. An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError, but the call succeeded and returned {result!r}")


def _ignore_notfound(fn) -> None:
    try:
        fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        code = resp.get("Error", {}).get("Code") if isinstance(resp, dict) else None
        if code not in ("ResourceNotFoundException", None):
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
