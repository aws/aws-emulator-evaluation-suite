"""list-analyzers-account-type-tracks-exact-membership."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-analyzers-account-type-tracks-exact-membership"
GROUP = "state-machine"
SERVICES = ["accessanalyzer"]

_SECOND_ACCOUNT_REFUSED = ("ServiceQuotaExceededException", "Analyzer limit exceeded")


def _expect_error(fn, code: str, message: str) -> None:
    """Assert fn() raises exactly (code, message); an unexpected success names what came back."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response["Error"]
        assert error["Code"] == code, (
            f"expected code {code!r}, got {error['Code']!r}: {error.get('Message')!r}"
        )
        assert error.get("Message") == message, (
            f"expected message {message!r}, got {error.get('Message')!r}"
        )
        return
    raise AssertionError(f"expected {code} ({message!r}), call returned {result!r} instead")


def _account_type_listing(aa) -> dict:
    """{name: arn} of every analyzer ListAnalyzers(type=ACCOUNT) names, across pages."""
    entries = {}
    paginator = aa.get_paginator("list_analyzers")
    for page in paginator.paginate(type="ACCOUNT"):
        for analyzer in page["analyzers"]:
            entries[analyzer["name"]] = analyzer["arn"]
    return entries


def _poll_account_type_listing(aa, stop_when, timeout_s: float = 60.0, interval_s: float = 2.0) -> dict:
    """Re-read ListAnalyzers(type=ACCOUNT) until stop_when(listing) holds; raise at the deadline."""
    deadline = time.monotonic() + timeout_s
    listing = _account_type_listing(aa)
    while not stop_when(listing):
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"ListAnalyzers(type=ACCOUNT) still reads {listing} after {timeout_s}s"
            )
        time.sleep(interval_s)
        listing = _account_type_listing(aa)
    return listing


def _delete_quietly(aa, name: str) -> None:
    try:
        aa.delete_analyzer(analyzerName=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
    "resource:account-singleton:accessanalyzer-account-analyzer",
)
def run(ctx) -> None:
    """ListAnalyzers(type=ACCOUNT) names exactly the account's one ACCOUNT analyzer, unmoved
    by an alongside ACCOUNT_UNUSED_ACCESS create and by a refused second ACCOUNT create, and
    drops it then names the recreated one once it is deleted and recreated under the same name."""
    aa = ctx.client("accessanalyzer")
    account_name = ctx.unique_name("sim2real-behav-aa-track-")
    unused_access_name = ctx.unique_name("sim2real-behav-aa-track-ua-")
    second_account_name = ctx.unique_name("sim2real-behav-aa-track-second-")

    first_arn = aa.create_analyzer(analyzerName=account_name, type="ACCOUNT")["arn"]
    ctx.on_cleanup(lambda: _delete_quietly(aa, account_name))

    listing = _poll_account_type_listing(aa, lambda ls: account_name in ls)
    assert listing == {account_name: first_arn}, (
        f"expected ListAnalyzers(type=ACCOUNT) to name exactly {{{account_name!r}: {first_arn!r}}}, "
        f"got {listing}"
    )

    unused_access_arn = aa.create_analyzer(
        analyzerName=unused_access_name, type="ACCOUNT_UNUSED_ACCESS"
    )["arn"]
    ctx.on_cleanup(lambda: _delete_quietly(aa, unused_access_name))
    assert unused_access_arn != first_arn, (
        f"expected a distinct arn for the unused-access analyzer, got {unused_access_arn!r} twice"
    )

    listing = _account_type_listing(aa)
    assert listing == {account_name: first_arn}, (
        f"an ACCOUNT_UNUSED_ACCESS create alongside it moved the ACCOUNT-type listing to {listing}"
    )

    _expect_error(
        lambda: aa.create_analyzer(analyzerName=second_account_name, type="ACCOUNT"),
        *_SECOND_ACCOUNT_REFUSED,
    )

    listing = _account_type_listing(aa)
    assert listing == {account_name: first_arn}, (
        f"a refused second ACCOUNT create moved the ACCOUNT-type listing to {listing}"
    )

    aa.delete_analyzer(analyzerName=account_name)
    listing = _poll_account_type_listing(aa, lambda ls: account_name not in ls)
    assert listing == {}, (
        f"expected ListAnalyzers(type=ACCOUNT) to name nothing once the analyzer is deleted, "
        f"got {listing}"
    )

    replacement_arn = aa.create_analyzer(analyzerName=account_name, type="ACCOUNT")["arn"]
    listing = _poll_account_type_listing(aa, lambda ls: account_name in ls)
    assert listing == {account_name: replacement_arn}, (
        f"expected ListAnalyzers(type=ACCOUNT) to name exactly the recreated analyzer "
        f"{{{account_name!r}: {replacement_arn!r}}}, got {listing}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
