"""put-parameter-typed-data-types-round-trip."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "put-parameter-typed-data-types-round-trip"
GROUP = "parameter-data-types"
SERVICES = ["ssm"]

_STANDARD_TIER_CASES = [
    ("aws:region", "us-east-1"),
    ("aws:account:id", "111122223333"),
    ("boolean", "true"),
    ("integer", "443"),
    ("float", "3.14"),
    ("binary", "101101"),
    ("hostname", "myhost"),
    ("email", "mary_major@example.com"),
    ("ipv4-address", "192.0.2.1"),
    ("ipv6-address", "2001:db8::1"),
]

_ADVANCED_TIER_CASES = [
    ("url", "https://example.com"),
    ("json", '{"port": 443}'),
    ("jsonc", '{"port": 443 /* HTTPS */}'),
]


@tags("axis:happy-path", "cap:c1", "concern:data-plane", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """PutParameter accepts each documented typed DataType with a conforming value, and
    GetParameter echoes the same DataType with the value as a string.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-data-types.html
    """
    ssm = ctx.client("ssm")

    def _put_and_check(data_type: str, value: str, tier: str) -> None:
        name = "/" + ctx.unique_name(
            "sim2real-behav-dtype-" + data_type.replace(":", "-").replace("-address", "") + "-"
        )
        put = ssm.put_parameter(
            Name=name, Value=value, Type="String", DataType=data_type, Tier=tier,
        )
        ctx.on_cleanup(lambda name=name: ssm.delete_parameter(Name=name))
        assert put["Version"] == 1, f"{data_type}: expected Version 1, got {put['Version']!r}"

        got = ssm.get_parameter(Name=name)["Parameter"]
        assert got["DataType"] == data_type, (
            f"{data_type}: GetParameter returned DataType {got['DataType']!r}"
        )
        assert isinstance(got["Value"], str), f"{data_type}: Value was not a string: {got['Value']!r}"
        assert got["Value"] == value, f"{data_type}: GetParameter returned Value {got['Value']!r}"

    for data_type, value in _STANDARD_TIER_CASES:
        _put_and_check(data_type, value, "Standard")

    for data_type, value in _ADVANCED_TIER_CASES:
        _put_and_check(data_type, value, "Advanced")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
