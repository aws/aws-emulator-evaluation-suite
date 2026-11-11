"""cache-parameter-invalid-value-rejected."""
from __future__ import annotations

from typing import Any

from behavioral_harness import tags

CHECK = "cache-parameter-invalid-value-rejected"
GROUP = "server-side"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyCacheParameterGroup rejects maxmemory-policy "not-a-real-policy" with InvalidParameterValue and
    the exact allowed-values message, and the previously set allkeys-lru stays in place with Source user."""
    ec = ctx.client("elasticache")
    name = ctx.unique_name("sim2real-behav-pg-")
    ec.create_cache_parameter_group(
        CacheParameterGroupName=name,
        CacheParameterGroupFamily="redis7",
        Description="sim2real invalid parameter value rejection check",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    ctx.on_cleanup(lambda: ec.delete_cache_parameter_group(CacheParameterGroupName=name))

    # Positive control: maxmemory-policy is a documented enum parameter.
    ec.modify_cache_parameter_group(
        CacheParameterGroupName=name,
        ParameterNameValues=[{"ParameterName": "maxmemory-policy", "ParameterValue": "allkeys-lru"}],
    )
    before = _param(ec, name, "maxmemory-policy")
    assert before["ParameterValue"] == "allkeys-lru", (
        f"expected maxmemory-policy=allkeys-lru after a legal modify, got {before!r}"
    )
    assert before["Source"] == "user", f"expected user-set source after a legal modify, got {before!r}"

    code, message = _error(
        lambda: ec.modify_cache_parameter_group(
            CacheParameterGroupName=name,
            ParameterNameValues=[
                {"ParameterName": "maxmemory-policy", "ParameterValue": "not-a-real-policy"}
            ],
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    assert message == (
        "invalid parameter value, allowed values are:volatile-lru,allkeys-lru,volatile-lfu,"
        "allkeys-lfu,volatile-random,allkeys-random,volatile-ttl,noeviction"
    ), f"unexpected InvalidParameterValue message: {message!r}"

    # Effect absent: the previously-accepted value must still be in place.
    after = _param(ec, name, "maxmemory-policy")
    assert after["ParameterValue"] == "allkeys-lru", (
        f"out-of-range value was rejected but the parameter was mutated anyway: {after!r}"
    )
    assert after["Source"] == "user", (
        f"rejected modify changed maxmemory-policy Source away from the prior user value: {after!r}"
    )


def _param(ec: Any, group_name: str, param_name: str) -> dict:
    marker = None
    while True:
        kwargs = {"CacheParameterGroupName": group_name}
        if marker:
            kwargs["Marker"] = marker
        resp = ec.describe_cache_parameters(**kwargs)
        for p in resp.get("Parameters", []):
            if p["ParameterName"] == param_name:
                return p
        marker = resp.get("Marker")
        if not marker:
            raise AssertionError(f"parameter {param_name} not found in group {group_name}")


def _error(fn):
    """Call fn(); return (code, message) from the ClientError it raises. An unexpected
    success raises, so a target that accepts what AWS refuses fails loudly."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
