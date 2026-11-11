"""op-contract-getResponseHeadersPolicy."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-getResponseHeadersPolicy"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetResponseHeadersPolicy round-trips a created policy's config; a bogus Id yields NoSuchResponseHeadersPolicy."""
    cf = ctx.client("cloudfront")
    name = ctx.unique_name("sim2real-rhp-")
    config = {
        "Name": name,
        "Comment": "sim2real behavioral check",
        "CustomHeadersConfig": {
            "Quantity": 1,
            "Items": [{"Header": "X-Sim2Real-Check", "Value": "true", "Override": True}],
        },
    }
    created = cf.create_response_headers_policy(ResponseHeadersPolicyConfig=config)
    policy_id = created["ResponseHeadersPolicy"]["Id"]
    created_etag = created["ETag"]
    ctx.on_cleanup(lambda: _delete_policy(cf, policy_id))

    got = cf.get_response_headers_policy(Id=policy_id)
    policy = got["ResponseHeadersPolicy"]
    assert policy["Id"] == policy_id, f"expected Id {policy_id!r}, got {policy['Id']!r}"
    got_name = policy["ResponseHeadersPolicyConfig"]["Name"]
    assert got_name == name, f"expected Name {name!r}, got {got_name!r}"
    got_comment = policy["ResponseHeadersPolicyConfig"]["Comment"]
    assert got_comment == "sim2real behavioral check", (
        f"expected Comment 'sim2real behavioral check', got {got_comment!r}"
    )
    headers = policy["ResponseHeadersPolicyConfig"]["CustomHeadersConfig"]
    assert headers["Quantity"] == 1, f"expected CustomHeadersConfig.Quantity 1, got {headers['Quantity']!r}"
    got_header = headers["Items"][0]["Header"]
    assert got_header == "X-Sim2Real-Check", f"expected Header 'X-Sim2Real-Check', got {got_header!r}"
    got_value = headers["Items"][0]["Value"]
    assert got_value == "true", f"expected Value 'true', got {got_value!r}"
    assert got["ETag"] == created_etag, f"expected ETag {created_etag!r} to round-trip, got {got['ETag']!r}"

    code, msg = _error(lambda: cf.get_response_headers_policy(Id="NOSUCHPOLICYID000000"))
    assert code == "NoSuchResponseHeadersPolicy", f"expected NoSuchResponseHeadersPolicy, got {code}"
    assert msg == "Id format is invalid", f"unexpected NoSuchResponseHeadersPolicy message: {msg!r}"

    # the cleanup delete is otherwise unasserted: prove it actually removes the policy.
    cf.delete_response_headers_policy(Id=policy_id, IfMatch=got["ETag"])
    code_after_delete, msg_after_delete = _error(lambda: cf.get_response_headers_policy(Id=policy_id))
    assert code_after_delete == "NoSuchResponseHeadersPolicy", (
        f"expected NoSuchResponseHeadersPolicy after delete, got {code_after_delete}"
    )
    assert msg_after_delete == "The specified response headers policy does not exist.", f"unexpected message after delete: {msg_after_delete!r}"


def _error(fn):
    """Call fn() and return the (code, message) of the ClientError it raises. A call that
    succeeds raises AssertionError: an emulator accepting input real AWS refuses must fail
    loudly, not read as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected a rejection, but the call SUCCEEDED and returned {result!r}")


def _delete_policy(cf, policy_id):
    try:
        cur = cf.get_response_headers_policy(Id=policy_id)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchResponseHeadersPolicy":
            raise
        return
    cf.delete_response_headers_policy(Id=policy_id, IfMatch=cur["ETag"])


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
