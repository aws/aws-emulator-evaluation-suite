"""allow-list-status-derivation-missing-object."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "allow-list-status-derivation-missing-object"
GROUP = "state"
SERVICES = ["macie2"]


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control", "resource:account-singleton:macie")
def run(ctx) -> None:
    """CreateAllowList with s3WordsList naming a missing object is refused with ValidationException and
    its exact message and leaves no list; a list naming a real object is created and reports status OK.
    """
    _ensure_macie_enabled(ctx)
    bucket = _create_scratch_bucket(ctx)
    macie = ctx.client("macie2")

    # Right after enable_macie(), CreateAllowList against an s3WordsList criteria can transiently
    # raise AccessDeniedException ("Macie is not authorized to access the required resources for
    # your account") while Macie's access to the account's S3 resources settles; retry through
    # that bounded window rather than reading it as a real rejection.
    rejected_name = ctx.unique_name("sim2real-macie-al-")
    code, message = _error_code(
        lambda: _create_allow_list_with_retry(
            macie,
            name=rejected_name,
            clientToken=ctx.unique_name("sim2real-macie-al-tok-"),
            criteria={"s3WordsList": {"bucketName": bucket, "objectKey": "does-not-exist.txt"}},
        )
    )
    assert code == "ValidationException", f"expected ValidationException, got {code!r}"
    expected_message = f"The S3 object doesn't exist: {bucket}, does-not-exist.txt"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    # Effect must be absent: no allow list was created as a side effect of the failed call.
    names = {a.get("name") for a in _list_all_allow_lists(macie)}
    assert rejected_name not in names, f"rejected allow list {rejected_name!r} was created anyway"

    # Positive control: pointing at a real object succeeds and reports a non-error status.
    s3 = ctx.client("s3")
    s3.put_object(Bucket=bucket, Key="wordlist.txt", Body=b"secretword\n")
    ctx.on_cleanup(lambda: s3.delete_object(Bucket=bucket, Key="wordlist.txt"))
    accepted_name = ctx.unique_name("sim2real-macie-al-ok-")
    allow_list_id = _create_allow_list_with_retry(
        macie,
        name=accepted_name,
        clientToken=ctx.unique_name("sim2real-macie-al-ok-tok-"),
        criteria={"s3WordsList": {"bucketName": bucket, "objectKey": "wordlist.txt"}},
        tags={"sim2real-check": CHECK},
    )["id"]
    ctx.on_cleanup(lambda: macie.delete_allow_list(id=allow_list_id, ignoreJobChecks="true"))

    listed = [a for a in _list_all_allow_lists(macie) if a.get("name") == accepted_name]
    assert [a.get("id") for a in listed] == [allow_list_id], (
        f"expected exactly the accepted allow list {allow_list_id!r} under {accepted_name!r}, got {listed!r}"
    )

    status = _poll_until(
        lambda: macie.get_allow_list(id=allow_list_id).get("status", {}).get("code"),
        lambda c: c is not None,
        timeout_s=90,
        interval_s=3,
    )
    assert status == "OK", f"expected status OK, got {status!r}"


def _create_allow_list_with_retry(macie, **kwargs):
    import time
    from botocore.exceptions import ClientError

    deadline = time.monotonic() + 60
    last_exc = None
    while time.monotonic() < deadline:
        try:
            return macie.create_allow_list(**kwargs)
        except ClientError as exc:
            err = exc.response["Error"]
            if err["Code"] == "AccessDeniedException" and "not authorized to access the required resources" in err.get("Message", ""):
                last_exc = exc
                time.sleep(2)
                continue
            raise
    raise AssertionError(f"create_allow_list still access-denied after settling window: {last_exc}")


def _poll_until(probe, predicate, timeout_s=60.0, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while time.monotonic() < deadline:
        last = probe()
        if predicate(last):
            return last
        time.sleep(interval_s)
    raise AssertionError(f"condition not met within {timeout_s}s (last={last!r})")


def _ensure_macie_enabled(ctx) -> None:
    """Enable Macie when the account has no session, and disable it again at cleanup so the
    account-wide setting ends in the state it started in."""
    from botocore.exceptions import ClientError

    macie = ctx.client("macie2")
    try:
        macie.get_macie_session()
        return
    except ClientError as exc:
        code = exc.response["Error"]["Code"]
        if code not in ("ResourceNotFoundException", "AccessDeniedException"):
            raise
    try:
        macie.enable_macie()
    except ClientError as exc2:
        if exc2.response["Error"]["Code"] != "ConflictException":
            raise
        return
    ctx.on_cleanup(macie.disable_macie)


def _create_scratch_bucket(ctx) -> str:
    s3 = ctx.client("s3")
    name = ctx.unique_name("sim2real-macie-")
    kwargs = {"Bucket": name}
    if ctx.region != "us-east-1":
        kwargs["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**kwargs)
    ctx.on_cleanup(lambda: s3.delete_bucket(Bucket=name))
    s3.put_bucket_tagging(Bucket=name, Tagging={"TagSet": [{"Key": "sim2real-check", "Value": CHECK}]})
    return name


def _error_code(fn):
    """Call fn(); return its error (code, message). An unexpected SUCCESS raises, because an
    over-permissive target accepting a call real AWS refuses is the strongest signal available."""
    from botocore.exceptions import ClientError

    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message")
    raise AssertionError(f"expected rejection, but the call SUCCEEDED and returned {result!r}")


def _list_all_allow_lists(macie):
    items = []
    next_token = None
    for _ in range(20):
        kwargs = {"nextToken": next_token} if next_token else {}
        resp = macie.list_allow_lists(**kwargs)
        items.extend(resp.get("allowLists", []))
        next_token = resp.get("nextToken")
        if not next_token:
            break
    return items


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
