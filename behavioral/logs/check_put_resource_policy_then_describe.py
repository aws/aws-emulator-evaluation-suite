"""put-resource-policy-then-describe."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-resource-policy-then-describe"
GROUP = 'resource-policy'
SERVICES = ['logs']

@tags("axis:happy-path", "cap:c1", "concern:representation", "concern:negative-classes", "plane:control", "resource:account-singleton:logs-resource-policy")
def run(ctx) -> None:
    """PutResourcePolicy makes the policy visible via DescribeResourcePolicies; deleting it
    removes it from that same list, and a second delete of the same name reports
    ResourceNotFoundException rather than silently succeeding again."""
    svc = ctx.client("logs")
    policy_name = ctx.unique_name("sim2real-behav-policy-")
    policy_doc = (
        '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
        '"Principal":{"Service":"es.amazonaws.com"},"Action":"logs:PutLogEvents",'
        '"Resource":"*"}]}'
    )
    svc.put_resource_policy(policyName=policy_name, policyDocument=policy_doc)
    ctx.on_cleanup(lambda: _delete_if_exists(svc, policy_name))

    resp = svc.describe_resource_policies()
    matches = [p for p in resp.get("resourcePolicies", []) if p["policyName"] == policy_name]
    assert len(matches) == 1, f"expected exactly one policy named {policy_name}, got {matches}"

    svc.delete_resource_policy(policyName=policy_name)
    remaining = [
        p["policyName"]
        for p in svc.describe_resource_policies().get("resourcePolicies", [])
        if p["policyName"] == policy_name
    ]
    assert remaining == [], f"expected {policy_name} gone after delete, still present: {remaining}"

    code, message = _client_error(lambda: svc.delete_resource_policy(policyName=policy_name))
    assert code == "ResourceNotFoundException", f"expected ResourceNotFoundException, got {code}"
    assert message == f"Policy with name [{policy_name}] does not exist.", (
        f"unexpected message: {message!r}"
    )


def _client_error(fn):
    """Call fn(); return its (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _delete_if_exists(svc, policy_name):
    try:
        svc.delete_resource_policy(policyName=policy_name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
