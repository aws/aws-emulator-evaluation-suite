"""slowlog-parameters-round-trip-and-reject-negative-length."""
from __future__ import annotations

from typing import Any

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "slowlog-parameters-round-trip-and-reject-negative-length"
GROUP = "negative-classes"
SERVICES = ["elasticache"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A negative slowlog-max-len is refused and leaves the system default, while the slow-log
    threshold and length set together persist as user values that apply immediately."""
    ec = ctx.client("elasticache")

    group = ctx.unique_name("sim2real-ec-slowlog-")
    ec.create_cache_parameter_group(
        CacheParameterGroupName=group,
        CacheParameterGroupFamily="redis7",
        Description="sim2real slow-log parameters",
        Tags=[{"Key": "sim2real:managed", "Value": "true"}],
    )
    ctx.on_cleanup(lambda: _delete_group(ec, group))

    allowed = _parameter(ec, group, "slowlog-max-len")["AllowedValues"]
    code, message = _error(
        lambda: ec.modify_cache_parameter_group(
            CacheParameterGroupName=group,
            ParameterNameValues=[{"ParameterName": "slowlog-max-len", "ParameterValue": "-5"}],
        )
    )
    assert code == "InvalidParameterValue", f"expected InvalidParameterValue, got {code!r}: {message!r}"
    expected = f"value:-5 is outside of range:{allowed}"
    assert message == expected, f"expected message {expected!r}, got {message!r}"
    untouched = _parameter(ec, group, "slowlog-max-len")
    assert untouched["Source"] == "system", f"the refused value changed the parameter: {untouched!r}"

    ec.modify_cache_parameter_group(
        CacheParameterGroupName=group,
        ParameterNameValues=[
            {"ParameterName": "slowlog-log-slower-than", "ParameterValue": "0"},
            {"ParameterName": "slowlog-max-len", "ParameterValue": "256"},
        ],
    )
    for name, value in (("slowlog-log-slower-than", "0"), ("slowlog-max-len", "256")):
        param = _parameter(ec, group, name)
        assert (param["ParameterValue"], param["Source"]) == (value, "user"), (
            f"expected {name}={value!r} as a user value, got {param!r}"
        )
        assert param["ChangeType"] == "immediate", (
            f"expected {name} to apply immediately, got ChangeType={param.get('ChangeType')!r}"
        )


def _parameter(ec: Any, group: str, name: str) -> dict:
    for page in ec.get_paginator("describe_cache_parameters").paginate(
        CacheParameterGroupName=group
    ):
        for param in page["Parameters"]:
            if param["ParameterName"] == name:
                return param
    raise AssertionError(f"parameter {name!r} not found in group {group!r}")


def _error(fn: Any) -> tuple[str, str | None]:
    """(Error.Code, Error.Message) of the ClientError ``fn`` raises; a success raises."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def _delete_group(ec: Any, group: str) -> None:
    try:
        ec.delete_cache_parameter_group(CacheParameterGroupName=group)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "CacheParameterGroupNotFound":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
