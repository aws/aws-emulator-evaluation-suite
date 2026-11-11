"""list-secrets-pagination-nexttoken-and-sort-order."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ForceDeleteWithoutRecovery: DeleteSecret's minimum recovery window is 7 days and a
# PendingDeletion secret still bills.


def _reap_secret(sm, secret_id, *, timeout_s=60.0, interval_s=2.0):
    """Irreversibly destroy a secret this check minted, then confirm it is gone."""
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
            raise
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            sm.describe_secret(SecretId=secret_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "ResourceNotFoundException":
                return
            raise
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"secret {secret_id} still present {timeout_s}s after "
                f"ForceDeleteWithoutRecovery; it bills $0.40/month until reaped"
            )
        time.sleep(interval_s)


def _create_secret(sm, ctx, name, **kwargs):
    """Create a secret, register its reaping teardown, and return the raw response."""
    resp = sm.create_secret(
        Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}], **kwargs
    )
    ctx.on_cleanup(lambda: _reap_secret(sm, resp["ARN"]))
    return resp


def _error_code(fn):
    """Call fn(); return the (Error.Code, Error.Message) it raised; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s=90.0, interval_s=3.0):
    """Bounded poll; returns the last observation whether or not the predicate held."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)
        last = probe()
    return last


CHECK = "list-secrets-pagination-nexttoken-and-sort-order"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']


@tags("axis:happy-path", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSecrets with MaxResults=1 pages one match at a time, omits NextToken on the last page,
    the pages partition the matches, SortBy=name asc/desc gives exact reversed sequences, and a
    fabricated NextToken is refused with InvalidNextTokenException.
    """
    sm = ctx.client("secretsmanager")
    base = ctx.unique_name("sim2real-behav-lspage-")
    # Suffixes chosen so lexicographic name order is unambiguous and is NOT the
    # creation order -- an emulator that sorts by insertion fails the asc case.
    suffixes = ["-c", "-a", "-b"]
    arns = {}
    for suf in suffixes:
        created = _create_secret(
            sm, ctx, base + suf, SecretString="sim2real-not-a-real-secret"
        )
        arns[base + suf] = created["ARN"]
    expected_names = sorted(arns)
    assert expected_names == [base + "-a", base + "-b", base + "-c"], (
        f"suffixes -c/-a/-b must sort lexicographically to -a/-b/-c, got {expected_names}"
    )

    name_filter = [{"Key": "name", "Values": [base]}]

    def _all_names():
        return sorted(
            s["Name"] for s in sm.list_secrets(Filters=name_filter)["SecretList"]
        )

    # ListSecrets is eventually consistent; establish the fixture before asserting on it.
    settled = _poll(_all_names, lambda got: got == expected_names)
    assert settled == expected_names, (
        f"the name filter {base!r} must converge on exactly the 3 created secrets; "
        f"last observation was {settled}"
    )

    # Manual NextToken walk -- deliberately not the botocore paginator, so the
    # token itself is under test.
    pages, token, guard = [], None, 0
    while True:
        guard += 1
        assert guard <= 6, "NextToken walk did not terminate within 6 pages for 3 secrets"
        kwargs = {"Filters": name_filter, "MaxResults": 1}
        if token is not None:
            kwargs["NextToken"] = token
        resp = sm.list_secrets(**kwargs)
        page = [s["Name"] for s in resp["SecretList"]]
        assert len(page) <= 1, f"MaxResults=1 must cap the page at one entry, got {page}"
        pages.append(page)
        token = resp.get("NextToken")
        if token is None:
            break
        assert token, f"NextToken must be omitted rather than empty, got {token!r}"

    assert "NextToken" not in resp, (
        "the final page must OMIT NextToken; a caller looping on its presence "
        f"otherwise never terminates. Final page keys: {sorted(resp)}"
    )
    flat = [n for page in pages for n in page]
    assert sorted(flat) == expected_names, (
        f"the pages must partition the 3 matches exactly; walked {pages}"
    )
    assert len(flat) == len(set(flat)), f"a secret appeared on two pages: {pages}"
    assert 3 <= len(pages) <= 4, (
        f"MaxResults=1 over 3 matches must take 3 pages (a trailing empty page is "
        f"tolerated); got {len(pages)} pages: {pages}"
    )

    # Ordering is asserted as an exact sequence; name order is wall-clock independent.
    asc = [
        s["Name"]
        for s in sm.list_secrets(Filters=name_filter, SortBy="name", SortOrder="asc")[
            "SecretList"
        ]
    ]
    assert asc == expected_names, (
        f"SortBy=name SortOrder=asc must return exactly {expected_names}, got {asc}"
    )
    desc = [
        s["Name"]
        for s in sm.list_secrets(Filters=name_filter, SortBy="name", SortOrder="desc")[
            "SecretList"
        ]
    ]
    assert desc == list(reversed(expected_names)), (
        f"SortBy=name SortOrder=desc must return exactly {list(reversed(expected_names))}, got {desc}"
    )

    # A fabricated continuation token must be refused, not treated as "start over".
    code, message = _error_code(
        lambda: sm.list_secrets(
            Filters=name_filter, MaxResults=1, NextToken="sim2real-not-a-real-token"
        )
    )
    assert code == "InvalidNextTokenException", (
        "a fabricated NextToken must raise InvalidNextTokenException rather than "
        f"silently restarting the listing, got {code}"
    )
    assert message == "The pagination token is no longer valid.", f"unexpected refusal message: {message!r}"

    # Control: the unpaginated filtered listing still works after the error.
    final = _all_names()
    assert final == expected_names, (
        f"the filtered listing must still work after the fabricated NextToken was "
        f"rejected, expected {expected_names}, got {final}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
