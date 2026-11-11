"""list-registries-scope-filter-local-vs-aws."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-registries-scope-filter-local-vs-aws"
GROUP = "data-plane"
SERVICES = ["schemas"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListRegistries Scope=AWS returns only built-in registries; Scope=LOCAL returns only custom ones."""
    schemas = ctx.client("schemas")
    registry = ctx.unique_name("sim2real-schemas-reg-")
    created = schemas.create_registry(RegistryName=registry)
    schemas.tag_resource(ResourceArn=created["RegistryArn"], Tags={"Owner": "sim2real"})

    def _cleanup_registry_if_present():
        try:
            schemas.delete_registry(RegistryName=registry)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup_registry_if_present)

    aws_scope = schemas.list_registries(Scope="AWS")
    aws_names = {r["RegistryName"] for r in aws_scope["Registries"]}
    assert "aws.events" in aws_names, f"built-in aws.events registry missing from Scope=AWS: {aws_names}"
    assert registry not in aws_names, f"custom registry {registry!r} leaked into Scope=AWS: {aws_names}"

    local_scope = schemas.list_registries(Scope="LOCAL")
    local_names = {r["RegistryName"] for r in local_scope["Registries"]}
    assert registry in local_names, f"custom registry {registry!r} missing from Scope=LOCAL: {local_names}"
    assert "aws.events" not in local_names, f"built-in aws.events registry leaked into Scope=LOCAL: {local_names}"

    # DeleteRegistry proves gone: absent from the list, DescribeRegistry 404s, and a mutation on
    # the dead id is refused with the same specific code.
    schemas.delete_registry(RegistryName=registry)

    after_delete = schemas.list_registries(Scope="LOCAL")
    after_names = {r["RegistryName"] for r in after_delete["Registries"]}
    assert registry not in after_names, (
        f"deleted registry {registry!r} still listed under Scope=LOCAL: {after_names}"
    )

    describe_err = _error(lambda: schemas.describe_registry(RegistryName=registry))
    assert describe_err["Code"] == "NotFoundException", (
        f"DescribeRegistry on a deleted registry returned {describe_err!r}, not NotFoundException"
    )
    assert describe_err["Message"] == f"Registry with name {registry} does not exist.", f"unexpected describe_registry_deleted message: {describe_err['Message']!r}"

    update_err = _error(lambda: schemas.update_registry(RegistryName=registry, Description="x"))
    assert update_err["Code"] == "NotFoundException", (
        f"UpdateRegistry on a deleted registry returned {update_err!r}, not NotFoundException"
    )
    assert update_err["Message"] == f"Registry with name {registry} does not exist.", f"unexpected update_registry_deleted message: {update_err['Message']!r}"


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
