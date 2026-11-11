"""create-environment-host-nonexistent-environment-validation-exception."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-environment-host-nonexistent-environment-validation-exception"
GROUP = "errors"
SERVICES = ["evs"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateEnvironmentHost has no ResourceNotFoundException in its error contract
    (unlike most other EVS operations); a nonexistent environmentId is surfaced as
    ValidationException instead."""
    evs = ctx.client("evs")
    code, message = _error(
        lambda: evs.create_environment_host(
            environmentId="env-0000000000",
            host={
                "hostName": ctx.unique_name("sim2real-host-")[:63],
                "keyName": "sim2real-evs-key",
                "instanceType": "i4i.metal",  # large-instance: EVS is metal-only; refused, launches nothing
            },
        )
    )
    assert code == "ValidationException", (
        f"expected ValidationException for a well-formed but nonexistent "
        f"environmentId (CreateEnvironmentHost has no ResourceNotFoundException "
        f"in its error contract), got {code!r}"
    )
    assert message == "env-0000000000 was not found", f"unexpected message {message!r}"


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        return error["Code"], error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
