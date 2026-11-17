"""list-templates-invalid-status-filter-rejected."""

from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-templates-invalid-status-filter-rejected"
GROUP = "negative-classes"
SERVICES = ["network-security-manager"]


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """ListTemplates with a status value outside the enum is refused with ValidationException
    naming the allowed values, while status='ACTIVE', its legal neighbor, still succeeds.
    """
    nsm = ctx.client("network-security-manager")

    code, message = _error(lambda: nsm.list_templates(status="BOGUS"))
    assert code == "ValidationException", (
        f"ListTemplates with an out-of-enum status gave {code!r}, expected ValidationException"
    )
    assert message == (
        "1 validation error detected: Value 'BOGUS' at 'status' failed to satisfy constraint: "
        "Member must satisfy enum value set: [DRAFT, ACTIVE, DISABLED]"
    ), f"unexpected message {message!r}"

    control = nsm.list_templates(status="ACTIVE")
    assert "templates" in control, (
        f"ListTemplates with the legal neighbor status='ACTIVE' did not return a templates "
        f"list: {control!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
