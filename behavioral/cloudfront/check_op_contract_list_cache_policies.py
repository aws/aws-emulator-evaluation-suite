"""op-contract-listCachePolicies."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "op-contract-listCachePolicies"
GROUP = "error-semantics"
SERVICES = ["cloudfront"]


@tags("axis:rejection", "cap:c1", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListCachePolicies(Type=managed) returns the AWS-managed policies; an invalid
    Type value fails the classic XML request's enum validation with MalformedXML
    (not the JSON-API-style InvalidArgument)."""
    cf = ctx.client("cloudfront")

    resp = cf.list_cache_policies(Type="managed")
    body = resp["CachePolicyList"]
    assert body["Quantity"] > 0, "expected at least the AWS-managed cache policies to exist"
    names = [item["CachePolicy"]["CachePolicyConfig"]["Name"] for item in body["Items"]]
    assert all(item["Type"] == "managed" for item in body["Items"]), (
        f"ListCachePolicies(Type='managed') returned a non-managed item: {body['Items']}"
    )
    assert any(name.startswith("Managed-") for name in names), names

    code, msg = _error(lambda: cf.list_cache_policies(Type="not-a-real-policy-type"))
    assert code == "MalformedXML", f"expected MalformedXML, got {code}"
    assert msg == "1 validation error detected: Value 'not-a-real-policy-type' at 'type' failed to satisfy constraint: Member must satisfy enum value set: [custom, managed]", f"unexpected MalformedXML message: {msg!r}"


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


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
