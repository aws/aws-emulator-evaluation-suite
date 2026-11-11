"""concurrent-custom-data-identifier-idempotent-creation."""
from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed

from behavioral_harness import tags

CHECK = "concurrent-custom-data-identifier-idempotent-creation"
GROUP = "concurrency"
SERVICES = ["macie2"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """Concurrent CreateCustomDataIdentifier calls sharing one clientToken and parameters yield one id,
    or lose with ResourceInUseException, and ListCustomDataIdentifiers holds exactly that identifier.
    """
    _ensure_macie_enabled(ctx)
    macie = ctx.client("macie2")
    shared_token = ctx.unique_name("sim2real-macie-cdi-idem-")
    name = ctx.unique_name("sim2real-macie-cdi-idem-")
    regex = r"[A-Z]{2}\d{6}"

    def _create():
        from botocore.exceptions import ClientError

        try:
            return macie.create_custom_data_identifier(
                name=name, regex=regex, clientToken=shared_token, tags={"sim2real": CHECK}
            )["customDataIdentifierId"]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ResourceInUseException":
                return None
            raise

    with ThreadPoolExecutor(max_workers=6) as pool:
        futures = [pool.submit(_create) for _ in range(6)]
        results = [f.result() for f in as_completed(futures)]

    ids = [r for r in results if r is not None]
    assert len(ids) >= 1, "no concurrent call succeeded in creating the identifier"
    ctx.on_cleanup(lambda: macie.delete_custom_data_identifier(id=ids[0]))

    assert len(set(ids)) == 1, f"idempotent creation returned multiple distinct ids: {set(ids)}"

    # Effect must not be duplicated: exactly one identifier with this name exists.
    matches = [item for item in _list_all_identifiers(macie) if item["name"] == name]
    assert len(matches) == 1
    assert matches[0]["id"] == ids[0]


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
