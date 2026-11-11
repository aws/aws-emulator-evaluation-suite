"""custom-data-identifier-soft-delete-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "custom-data-identifier-soft-delete-lifecycle"
GROUP = "state"
SERVICES = ["macie2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """DeleteCustomDataIdentifier is a soft delete: the resource remains gettable with deleted=true,
    but a soft-deleted identifier no longer appears in the list of live identifiers."""
    _ensure_macie_enabled(ctx)
    macie = ctx.client("macie2")
    name = ctx.unique_name("sim2real-macie-cdi-")
    cdi_id = macie.create_custom_data_identifier(
        name=name,
        regex=r"[A-Z]{3}-\d{4}",
        clientToken=ctx.unique_name("sim2real-macie-cdi-tok-"),
        tags={"sim2real-check": CHECK},
    )["customDataIdentifierId"]
    ctx.on_cleanup(lambda: macie.delete_custom_data_identifier(id=cdi_id))

    before = macie.get_custom_data_identifier(id=cdi_id)
    assert before.get("deleted", False) is False, f"expected not-yet-deleted, got deleted={before.get('deleted')!r}"
    assert cdi_id in {item["id"] for item in _list_all_identifiers(macie)}, (
        f"expected {cdi_id} to be listed before delete"
    )

    macie.delete_custom_data_identifier(id=cdi_id)

    after = macie.get_custom_data_identifier(id=cdi_id)
    assert after["deleted"] is True, f"expected deleted=True after delete, got {after['deleted']!r}"
    assert after["name"] == name, f"expected name to survive soft delete, got {after['name']!r} != {name!r}"
    assert cdi_id not in {item["id"] for item in _list_all_identifiers(macie)}, (
        f"expected {cdi_id} to be excluded from the list after soft delete"
    )


def _list_all_identifiers(macie):
    items = []
    next_token = None
    for _ in range(20):
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = macie.list_custom_data_identifiers(**kwargs)
        items.extend(resp.get("items", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return items


def _ensure_macie_enabled(ctx) -> None:
    from botocore.exceptions import ClientError

    macie = ctx.client("macie2")
    try:
        macie.get_macie_session()
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("ResourceNotFoundException", "AccessDeniedException"):
            raise
        try:
            macie.enable_macie()
        except ClientError as exc2:
            if exc2.response["Error"]["Code"] != "ConflictException":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
