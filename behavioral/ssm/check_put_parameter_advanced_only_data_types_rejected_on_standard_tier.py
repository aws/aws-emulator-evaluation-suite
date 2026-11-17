"""put-parameter-advanced-only-data-types-rejected-on-standard-tier."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-parameter-advanced-only-data-types-rejected-on-standard-tier"
GROUP = "parameter-data-types"
SERVICES = ["ssm"]

_CASES = [
    ("url", "https://example.com",
     "The url data type is only supported for advanced parameters."),
    ("json", '{"port": 443}',
     "The json data type is only supported for advanced parameters."),
    ("jsonc", '{"port": 443 /* HTTPS */}',
     "The jsonc data type is only supported for advanced parameters."),
]


def _client_error(fn):
    """(code, message) of the ClientError fn() raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


def expect_error(fn, code, message) -> None:
    """Assert fn() is refused with exactly (code, message)."""
    got_code, got_message = _client_error(fn)
    assert got_code == code, f"expected code {code!r}, got {got_code!r}: {got_message!r}"
    assert got_message == message, f"expected message {message!r}, got {got_message!r}"


def _not_found_code(fn) -> str:
    """The Error.Code fn() raises; an unexpected success raises instead."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError(f"expected the parameter to be missing, but the read succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutParameter rejects url, json and jsonc on a standard-tier parameter, and the same
    DataType and value succeed once the parameter is created in the advanced tier.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-data-types.html
    """
    ssm = ctx.client("ssm")

    for data_type, value, message in _CASES:
        name = "/" + ctx.unique_name("sim2real-behav-dtype-tier-" + data_type + "-")

        _ADVANCED_ONLY = ("ValidationException", message)
        expect_error(
            lambda name=name, data_type=data_type, value=value: ssm.put_parameter(
                Name=name, Value=value, Type="String", DataType=data_type, Tier="Standard"
            ),
            *_ADVANCED_ONLY,
        )

        code = _not_found_code(lambda name=name: ssm.get_parameter(Name=name))
        assert code == "ParameterNotFound", (
            f"{data_type}: expected no parameter to exist after the refusal, got {code!r}"
        )

        # Positive control: the same DataType and value succeed on the advanced tier.
        put = ssm.put_parameter(Name=name, Value=value, Type="String", DataType=data_type, Tier="Advanced")
        ctx.on_cleanup(lambda name=name: ssm.delete_parameter(Name=name))
        assert put["Version"] == 1, f"{data_type}: expected Version 1, got {put['Version']!r}"

        got = ssm.get_parameter(Name=name)["Parameter"]
        assert got["DataType"] == data_type, f"{data_type}: GetParameter returned DataType {got['DataType']!r}"
        assert got["Value"] == value, f"{data_type}: GetParameter returned Value {got['Value']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
