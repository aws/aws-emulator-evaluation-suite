"""list-configuration-managers-max-items-out-of-range-rejected."""
from __future__ import annotations

from botocore.config import Config
from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-configuration-managers-max-items-out-of-range-rejected"
GROUP = "overly-permissive"
SERVICES = ["ssm-quicksetup"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListConfigurationManagers rejects MaxItems=101 and MaxItems=0 (outside 1-100) with server-side
    ValidationException and the exact messages, while MaxItems=100 is accepted."""
    qs = ctx.client("ssm-quicksetup")
    qs_unvalidated = ctx.client("ssm-quicksetup", config=Config(parameter_validation=False))

    err_high = _client_error(lambda: qs.list_configuration_managers(MaxItems=101))
    code_high = err_high.get("Code")
    assert code_high == "ValidationException", f"MaxItems=101: expected ValidationException, got {code_high!r}"
    expected_high = (
        "1 validation error detected: Value '101' at 'maxItems' failed to satisfy constraint: "
        "Member must have value less than or equal to 100"
    )
    assert err_high.get("Message") == expected_high, f"MaxItems=101: got message {err_high.get('Message')!r}"

    err_low = _client_error(lambda: qs_unvalidated.list_configuration_managers(MaxItems=0))
    code_low = err_low.get("Code")
    assert code_low == "ValidationException", f"MaxItems=0: expected ValidationException, got {code_low!r}"
    expected_low = (
        "1 validation error detected: Value '0' at 'maxItems' failed to satisfy constraint: "
        "Member must have value greater than or equal to 1"
    )
    assert err_low.get("Message") == expected_low, f"MaxItems=0: got message {err_low.get('Message')!r}"

    # positive control: the boundary value itself is accepted
    resp = qs.list_configuration_managers(MaxItems=100)
    assert "ConfigurationManagersList" in resp, f"MaxItems=100 should succeed, got {resp!r}"


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an emulator
    ACCEPTING input real AWS refuses is the strongest signal available."""
    try:
        result = fn()
    except ClientError as e:
        return e.response.get("Error", {})
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
