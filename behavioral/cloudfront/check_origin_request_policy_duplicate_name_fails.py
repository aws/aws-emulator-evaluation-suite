"""origin-request-policy-duplicate-name-fails."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error(fn):
    """Call fn(); return its botocore (code, message). A success raises: accepting input AWS refuses
    is a finding in itself, not a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")

def _force_delete(get_fn, delete_fn, resource_id):
    """ETag-guarded delete of a CloudFront policy-like resource."""
    resp = get_fn(Id=resource_id)
    delete_fn(Id=resource_id, IfMatch=resp["ETag"])

CHECK = "origin-request-policy-duplicate-name-fails"
GROUP = 'overly-permissive'
SERVICES = ['cloudfront']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateOriginRequestPolicy with a Name in use fails with OriginRequestPolicyAlreadyExists and its exact
    message, leaves the original policy untouched, and succeeds under a fresh Id once the original is deleted."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-behav-orp-")
    cfg = {
        "Comment": "behavioral test",
        "Name": name,
        "HeadersConfig": {"HeaderBehavior": "none"},
        "CookiesConfig": {"CookieBehavior": "none"},
        "QueryStringsConfig": {"QueryStringBehavior": "none"},
    }
    live = {"id": None}
    ctx.on_cleanup(
        lambda: live["id"] and _force_delete(
            cf.get_origin_request_policy, cf.delete_origin_request_policy, live["id"]
        )
    )

    create_resp = cf.create_origin_request_policy(OriginRequestPolicyConfig=cfg)
    policy_id = create_resp["OriginRequestPolicy"]["Id"]
    live["id"] = policy_id

    code, message = _error(lambda: cf.create_origin_request_policy(OriginRequestPolicyConfig=cfg))
    assert code == "OriginRequestPolicyAlreadyExists", (
        f"expected OriginRequestPolicyAlreadyExists on duplicate Name, got {code}"
    )
    expected = "Another origin request policy with the same name already exists within the aws account."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # effect absent: the original policy is untouched (same id, same config) — an independent
    # read through a different operation than the one that mutated
    still = cf.get_origin_request_policy(Id=policy_id)["OriginRequestPolicy"]
    assert still["Id"] == policy_id, f"expected original policy {policy_id} untouched, got {still['Id']}"
    assert still["OriginRequestPolicyConfig"]["Name"] == name

    # restore: free the name by deleting the original policy
    _force_delete(cf.get_origin_request_policy, cf.delete_origin_request_policy, policy_id)
    live["id"] = None

    # the identical call now succeeds once the name is free
    recreated = cf.create_origin_request_policy(OriginRequestPolicyConfig=cfg)["OriginRequestPolicy"]
    live["id"] = recreated["Id"]
    assert recreated["OriginRequestPolicyConfig"]["Name"] == name
    assert recreated["Id"] != policy_id, "expected a fresh policy id after recreation"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
