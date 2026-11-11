"""list-control-mappings-invalid-mapping-type-filter-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "list-control-mappings-invalid-mapping-type-filter-rejected"
GROUP = "overly-permissive"
SERVICES = ["controlcatalog"]

_MAPPING_TYPE_MESSAGE = (
    "1 validation error detected: Value at 'filter.mappingTypes' failed to satisfy constraint: "
    "Member must satisfy constraint: [Member must satisfy enum value set: "
    "[RELATED_CONTROL, COMMON_CONTROL, FRAMEWORK]]"
)


@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListControlMappings rejects a MappingTypes filter value outside the documented enum."""
    cc = ctx.client("controlcatalog")

    # positive control: a real enum value is accepted (regardless of how many mappings it matches)
    ok = cc.list_control_mappings(Filter={"MappingTypes": ["FRAMEWORK"]}, MaxResults=5)
    assert "ControlMappings" in ok, f"expected a well-formed ListControlMappings response, got {ok!r}"

    code, message = _error_code(
        lambda: cc.list_control_mappings(Filter={"MappingTypes": ["NOT_A_REAL_MAPPING_TYPE"]})
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a MappingTypes value outside the documented enum, got {code!r}"
    )
    assert message == _MAPPING_TYPE_MESSAGE, f"expected {_MAPPING_TYPE_MESSAGE!r}, got {message!r}"


def _error_code(fn):
    """Call fn(); return its botocore error code. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
