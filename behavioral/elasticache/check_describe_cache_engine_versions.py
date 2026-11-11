"""describe-cache-engine-versions."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _fault_base(code):
    """Strip the modeled Fault/Exception suffix so error codes compare on their base."""
    for suffix in ("Exception", "Fault"):
        if code and code.endswith(suffix) and len(code) > len(suffix):
            return code[: -len(suffix)]
    return code

def _error(fn, expected):
    """Call fn() and return its ClientError (code, message); raise if the call succeeds."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected {expected} but the call SUCCEEDED")

def _refusal(fn, expected):
    """(code without its modeled Fault/Exception suffix, message) of the error fn() raises."""
    code, message = _error(fn, expected)
    return _fault_base(code), message

CHECK = "describe-cache-engine-versions"
GROUP = 'discovery'
SERVICES = ['elasticache']

@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeCacheEngineVersions reports engine/family pairs and honours its filters."""
    ec = ctx.client("elasticache")
    resp = ec.describe_cache_engine_versions(Engine="redis")
    versions = resp["CacheEngineVersions"]
    assert versions, resp
    for v in versions:
        assert v["Engine"] == "redis", v
        assert v.get("EngineVersion"), v
        assert v.get("CacheParameterGroupFamily"), v

    # Filtering by family narrows the result set to that family only.
    family_resp = ec.describe_cache_engine_versions(
        Engine="redis", CacheParameterGroupFamily="redis7",
    )
    families = {v["CacheParameterGroupFamily"] for v in family_resp["CacheEngineVersions"]}
    assert families == {"redis7"}, families

    # An engine that does not exist is rejected outright, not answered with an
    # empty result set.
    refused = _refusal(
        lambda: ec.describe_cache_engine_versions(Engine="not-an-engine"),
        "InvalidParameterValueException",
    )
    assert refused == (
        "InvalidParameterValue",
        "Invalid engine name: not-an-engine",
    ), f"expected InvalidParameterValue with its exact message, got {refused!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
