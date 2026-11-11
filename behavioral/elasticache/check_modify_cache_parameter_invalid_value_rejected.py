"""modify-cache-parameter-invalid-value-rejected."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "modify-cache-parameter-invalid-value-rejected"
GROUP = "negative-classes"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ModifyCacheParameterGroup with a parameter value outside its documented allowed
    enum (maxmemory-policy) is rejected with InvalidParameterValue and does not persist."""
    ec = ctx.client("elasticache")

    group_name = ctx.unique_name("sim2real-ec-cpg-")
    ec.create_cache_parameter_group(
        CacheParameterGroupName=group_name,
        CacheParameterGroupFamily="redis7",
        Description="sim2real behavioral invalid-value check",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: ec.delete_cache_parameter_group(CacheParameterGroupName=group_name))

    code, message = _error(
        lambda: ec.modify_cache_parameter_group(
            CacheParameterGroupName=group_name,
            ParameterNameValues=[{"ParameterName": "maxmemory-policy", "ParameterValue": "not-a-real-policy"}],
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}"
    allowed = _find_parameter(ec, group_name, "maxmemory-policy")["AllowedValues"]
    expected_message = f"invalid parameter value, allowed values are:{allowed}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect absent: the parameter was not changed away from its system default.
    param = _find_parameter(ec, group_name, "maxmemory-policy")
    assert param["ParameterValue"] != "not-a-real-policy", param
    assert param["Source"] == "system", f"expected untouched system default, got {param}"

    # Positive control: a value within the documented enum is accepted and persists.
    ec.modify_cache_parameter_group(
        CacheParameterGroupName=group_name,
        ParameterNameValues=[{"ParameterName": "maxmemory-policy", "ParameterValue": "allkeys-lru"}],
    )
    param = _find_parameter(ec, group_name, "maxmemory-policy")
    assert param["ParameterValue"] == "allkeys-lru", param
    assert param["Source"] == "user", f"expected user-set source, got {param}"


def _find_parameter(ec: Any, group_name: str, parameter_name: str) -> dict:
    params = ec.describe_cache_parameters(CacheParameterGroupName=group_name)["Parameters"]
    for param in params:
        if param["ParameterName"] == parameter_name:
            return param
    raise AssertionError(f"parameter {parameter_name!r} not found in group {group_name!r}")


def _error(fn: Any) -> tuple[str, str | None]:
    """Call fn(); return (code, message) from the ClientError it must raise. An unexpected SUCCESS
    raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected a ClientError but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
