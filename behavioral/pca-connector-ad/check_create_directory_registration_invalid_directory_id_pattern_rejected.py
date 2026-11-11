"""create-directory-registration-invalid-directory-id-pattern-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-directory-registration-invalid-directory-id-pattern-rejected"
GROUP = "validation"
SERVICES = ["pca-connector-ad"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """CreateDirectoryRegistration rejects a DirectoryId that fails the ^d-[0-9a-f]{10}$
    pattern with ValidationException, creates no registration, and a plain
    ListDirectoryRegistrations call in the same file proves the endpoint is otherwise healthy.
    """
    pcad = ctx.client("pca-connector-ad")

    before = len(pcad.list_directory_registrations()["DirectoryRegistrations"])

    code, message = _error_code(
        lambda: pcad.create_directory_registration(DirectoryId="totally-not-a-directory-id")
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    assert message == (
        '[ECMA 262 regex "^d-[0-9a-f]{10}$" does not match input string '
        '"totally-not-a-directory-id"]'
    ), message

    after = len(pcad.list_directory_registrations()["DirectoryRegistrations"])
    assert after == before, "no directory registration must have been created"

    control = pcad.list_directory_registrations()
    assert "DirectoryRegistrations" in control, (
        "ListDirectoryRegistrations must still return its collection key after the rejected create"
    )


def _error_code(fn):
    try:
        result = fn()
    except Exception as exc:  # noqa: BLE001
        resp = getattr(exc, "response", None)
        if resp:
            err = resp.get("Error", {})
            return err.get("Code"), err.get("Message")
        return type(exc).__name__, str(exc)
    raise AssertionError(f"expected a rejection, call succeeded with {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
