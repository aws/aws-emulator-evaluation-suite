"""custom-data-identifier-invalid-regex-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "custom-data-identifier-invalid-regex-rejected"
GROUP = "overly-permissive"
SERVICES = ["macie2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """CreateCustomDataIdentifier refuses an invalid regex with ValidationException and its exact message
    and creates nothing, while two valid identifiers with the same name get distinct ids.
    """
    _ensure_macie_enabled(ctx)
    macie = ctx.client("macie2")
    name = ctx.unique_name("sim2real-macie-cdi-badregex-")

    before_count = len(_list_all_identifiers(macie))

    error = _reject(
        lambda: macie.create_custom_data_identifier(
            name=name,
            regex="[A-Z(unclosed",  # syntactically invalid regex
            clientToken=ctx.unique_name("sim2real-macie-cdi-tok-bad-"),
        ),
        ctx,
        macie,
    )
    assert error["Code"] == "ValidationException", (
        f"expected ValidationException for a syntactically invalid regex, got {error['Code']!r}"
    )
    assert error["Message"] == "Unsafe regex, keywords, or ignoreWords.", (
        f"unexpected message: {error['Message']!r}"
    )

    # Effect must be absent: the failed call created no identifier.
    after_bad_count = len(_list_all_identifiers(macie))
    assert after_bad_count == before_count, (
        f"a rejected CreateCustomDataIdentifier changed the identifier count from "
        f"{before_count} to {after_bad_count}"
    )

    # Positive control: a syntactically valid regex is accepted, even reusing the same name --
    # Macie's real API does not enforce name uniqueness for custom data identifiers.
    first_id = macie.create_custom_data_identifier(
        name=name,
        regex=r"[A-Z]{2}\d{6}",
        clientToken=ctx.unique_name("sim2real-macie-cdi-tok-a-"),
        tags={"sim2real-behav": CHECK},
    )["customDataIdentifierId"]
    ctx.on_cleanup(lambda: macie.delete_custom_data_identifier(id=first_id))

    second_id = macie.create_custom_data_identifier(
        name=name,
        regex=r"\d{4}",
        clientToken=ctx.unique_name("sim2real-macie-cdi-tok-b-"),
        tags={"sim2real-behav": CHECK},
    )["customDataIdentifierId"]
    ctx.on_cleanup(lambda: macie.delete_custom_data_identifier(id=second_id))
    assert second_id != first_id, (
        f"two CreateCustomDataIdentifier calls with distinct clientTokens and the same name "
        f"both resolved to the same id {second_id!r}"
    )

    matches = [item for item in _list_all_identifiers(macie) if item["name"] == name]
    assert len(matches) == 2, (
        f"expected 2 identifiers named {name!r} after two non-unique-name creates, found "
        f"{len(matches)}: {matches!r}"
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


def _reject(fn, ctx, macie):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises -- and, because it
    means real AWS accepted a syntactically invalid regex and created a real identifier, that
    identifier is registered for cleanup first so the over-permissive case does not also leak."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]
    created_id = result.get("customDataIdentifierId")
    if created_id:
        ctx.on_cleanup(lambda: macie.delete_custom_data_identifier(id=created_id))
    raise AssertionError(
        f"expected CreateCustomDataIdentifier to reject the invalid regex, but it SUCCEEDED "
        f"and created {created_id!r}"
    )


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

