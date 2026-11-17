"""put-parameter-rejects-malformed-typed-values."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "put-parameter-rejects-malformed-typed-values"
GROUP = "parameter-data-types"
SERVICES = ["ssm"]

_CASES = [
    ("aws:region", "us-east-1", "us-fake-1",
     "The parameter value is not a valid AWS Region. Please check "
     "https://docs.aws.amazon.com/global-infrastructure/latest/regions/aws-regions.html "
     "for the list of valid regions."),
    ("aws:account:id", "111122223333", "1111-2222-3333",
     "The parameter value is not a valid AWS account ID."),
    ("boolean", "true", "tRue",
     "The parameter value is not a valid boolean. Accepted values are true, True, TRUE, "
     "false, False, FALSE, 1 and 0."),
    ("integer", "443", "007",
     "The parameter value is not a valid integer. A value must be an optional minus sign "
     "followed by digits, with no leading zeros, no plus sign, no decimal point and no "
     "whitespace."),
    ("float", "3.14", "NaN",
     "The parameter value is not a valid float. A value must be a decimal number such as "
     "1.5, .5 or 2.5e-8, with an optional minus sign and no leading zeros. NaN and Infinity "
     "are not accepted."),
    ("binary", "101101", "1021101",
     "The parameter value is not a valid binary number. A value must be one or more binary "
     "digits, 0 or 1, with no prefix, sign, separator or whitespace."),
    ("hostname", "myhost", "_dmarc.example.com",
     "The parameter value is not a valid host name. It contains an underscore, which host "
     "names do not allow."),
    ("email", "mary_major@example.com", "Mary Major <mary_major@example.com>",
     "The parameter value is not a valid email address. It contains whitespace or a "
     "control character."),
    ("ipv4-address", "192.0.2.1", "192.0.2.1/32",
     "The parameter value is not a valid IPv4 address. It may contain only the digits 0 to "
     "9 and dots."),
    ("ipv6-address", "2001:db8::1", "[2001:db8::1]",
     "The parameter value is not a valid IPv6 address. It may contain only hexadecimal "
     "digits, colons, and the dots of an embedded IPv4 address. Zone IDs, brackets and "
     "prefix lengths are not accepted."),
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


@tags("axis:rejection", "cap:c1", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutParameter rejects a value that does not conform to its DataType with
    ValidationException, and the parameter's stored value is unaffected by the refusal.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-data-types.html
    """
    ssm = ctx.client("ssm")

    for data_type, valid_value, bad_value, message in _CASES:
        name = "/" + ctx.unique_name("sim2real-behav-dtype-bad-" + data_type.replace(":", "-") + "-")
        put = ssm.put_parameter(Name=name, Value=valid_value, Type="String", DataType=data_type)
        ctx.on_cleanup(lambda name=name: ssm.delete_parameter(Name=name))
        assert put["Version"] == 1, f"{data_type}: expected Version 1, got {put['Version']!r}"

        _MALFORMED = ("ValidationException", message)
        expect_error(
            lambda name=name, data_type=data_type, bad_value=bad_value: ssm.put_parameter(
                Name=name, Value=bad_value, Type="String", DataType=data_type, Overwrite=True
            ),
            *_MALFORMED,
        )

        got = ssm.get_parameter(Name=name)["Parameter"]
        assert got["Value"] == valid_value, (
            f"{data_type}: value became {got['Value']!r} after a rejected overwrite"
        )
        assert got["Version"] == 1, (
            f"{data_type}: version advanced to {got['Version']!r} after a rejected overwrite"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
