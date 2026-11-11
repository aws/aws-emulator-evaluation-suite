"""create-allow-list-mutually-exclusive-criteria-rejected."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "create-allow-list-mutually-exclusive-criteria-rejected"
GROUP = "overly-permissive"
SERVICES = ["macie2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """CreateAllowList with both regex and s3WordsList is refused with ValidationException and its exact
    message and creates no list, while a regex-only list is created.
    """
    _ensure_macie_enabled(ctx)
    macie = ctx.client("macie2")
    bad_name = ctx.unique_name("sim2real-macie-al-bad-")

    # Positive control: a single-criterion (regex-only) allow list is accepted.
    good_id = macie.create_allow_list(
        name=ctx.unique_name("sim2real-macie-al-good-"),
        clientToken=ctx.unique_name("sim2real-macie-al-tok-"),
        criteria={"regex": ".+"},
        tags={"sim2real": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: macie.delete_allow_list(id=good_id, ignoreJobChecks="true"))
    fetched = macie.get_allow_list(id=good_id)
    assert fetched["id"] == good_id, (
        f"positive control: expected get_allow_list({good_id!r}) to return that id, "
        f"got {fetched.get('id')!r}"
    )

    error = _client_error(
        lambda: macie.create_allow_list(
            name=bad_name,
            clientToken=ctx.unique_name("sim2real-macie-al-tok-"),
            criteria={
                "regex": ".+",
                "s3WordsList": {"bucketName": "some-bucket-name", "objectKey": "words.txt"},
            },
        )
    )
    assert error.get("Code") == "ValidationException", (
        f"expected CreateAllowList with both regex and s3WordsList set to be rejected with "
        f"ValidationException, got {error.get('Code')!r} ({error.get('Message')!r})"
    )
    assert error.get("Message") == (
        "Allow list criteria can specify a regex or an S3 object, but not both."
    ), f"unexpected message: {error.get('Message')!r}"

    # Effect must be absent: no allow list with that name exists.
    assert not _any_allow_list_named(macie, bad_name), (
        f"CreateAllowList was rejected but left behind an allow list named {bad_name!r}"
    )


def _any_allow_list_named(macie, name: str) -> bool:
    next_token = None
    for _ in range(20):
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = macie.list_allow_lists(**kwargs)
        for item in resp.get("allowLists", []):
            if item["name"] == name:
                return True
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return False


def _client_error(fn):
    """Call fn(); return its botocore Error dict. An unexpected SUCCESS raises."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}"
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
