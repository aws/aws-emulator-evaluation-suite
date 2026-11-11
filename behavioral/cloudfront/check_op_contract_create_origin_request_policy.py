"""op-contract-createOriginRequestPolicy."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "op-contract-createOriginRequestPolicy"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateOriginRequestPolicy echoes the submitted config; duplicate Name is rejected."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-orp-")

    config = {
        "Name": name,
        "Comment": "sim2real behavioral check",
        "HeadersConfig": {"HeaderBehavior": "none"},
        "CookiesConfig": {"CookieBehavior": "none"},
        "QueryStringsConfig": {"QueryStringBehavior": "none"},
    }
    resp = cf.create_origin_request_policy(OriginRequestPolicyConfig=config)
    policy = resp["OriginRequestPolicy"]
    policy_id = policy["Id"]
    ctx.on_cleanup(lambda: _delete_policy(ctx, policy_id))

    assert policy_id, "expected a non-empty policy Id in the create response"
    assert policy["OriginRequestPolicyConfig"] == config, (
        f"create response did not echo the submitted config: got {policy['OriginRequestPolicyConfig']!r}"
    )
    assert resp.get("ETag"), "expected an ETag on create"
    assert resp.get("Location"), "expected a Location header value"

    got = cf.get_origin_request_policy(Id=policy_id)["OriginRequestPolicy"]
    assert got["OriginRequestPolicyConfig"]["Name"] == name, (
        f"expected Name {name!r} on independent read, got {got['OriginRequestPolicyConfig']['Name']!r}"
    )

    # Distinct error boundary: a second policy with the same Name is rejected.
    code, message = _error(
        lambda: cf.create_origin_request_policy(
            OriginRequestPolicyConfig={**config, "Comment": "dup"}
        )
    )
    assert code == "OriginRequestPolicyAlreadyExists", f"expected OriginRequestPolicyAlreadyExists, got {code}"
    expected = "Another origin request policy with the same name already exists within the aws account."
    assert message == expected, f"expected message {expected!r}, got {message!r}"

    # Effect-absent beat: the rejected duplicate must not have mutated the original policy.
    unchanged = cf.get_origin_request_policy(Id=policy_id)["OriginRequestPolicy"]
    assert unchanged["OriginRequestPolicyConfig"]["Comment"] == config["Comment"], (
        f"duplicate-name rejection mutated the original policy's Comment: "
        f"expected {config['Comment']!r}, got {unchanged['OriginRequestPolicyConfig']['Comment']!r}"
    )


def _delete_policy(ctx, policy_id: str) -> None:
    cf = ctx.client("cloudfront")
    try:
        etag = cf.get_origin_request_policy(Id=policy_id)["ETag"]
        cf.delete_origin_request_policy(Id=policy_id, IfMatch=etag)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchOriginRequestPolicy":
            raise


def _error(fn):
    """Call fn(); return the ClientError (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
