"""create-registry-duplicate-name-rejected-conflict."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "create-registry-duplicate-name-rejected-conflict"
GROUP = "overly-permissive"
SERVICES = ["schemas"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Re-CreateRegistry on an existing name is rejected as ConflictException, leaving the original untouched."""
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    schemas.create_registry(RegistryName=registry, Description="first")
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=registry))

    err = _error(lambda: schemas.create_registry(RegistryName=registry, Description="second"))
    assert err["Code"] == "ConflictException", f"unexpected error: {err!r}"
    assert err["Message"] == f"Registry with name {registry} already exists.", f"unexpected create_registry_dup message: {err['Message']!r}"

    unaffected = schemas.describe_registry(RegistryName=registry)
    assert unaffected["Description"] == "first", (
        f"expected original description 'first' unaffected by rejected duplicate, got {unaffected['Description']!r}"
    )

    # Positive control: a genuinely new registry name still succeeds.
    other_registry = ctx.unique_name("sim2real-schemas-reg2-")
    schemas.create_registry(RegistryName=other_registry, Description="control")
    ctx.on_cleanup(lambda: schemas.delete_registry(RegistryName=other_registry))
    control = schemas.describe_registry(RegistryName=other_registry)
    assert control["Description"] == "control", (
        f"expected control registry description 'control', got {control['Description']!r}"
    )


def _error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises, because an
    emulator accepting a call real AWS refuses must not read as an error-code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    raise AssertionError(f"expected a ClientError, but the call SUCCEEDED and returned {result!r}")


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
