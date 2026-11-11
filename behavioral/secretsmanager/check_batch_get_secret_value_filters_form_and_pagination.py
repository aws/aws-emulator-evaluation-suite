"""batch-get-secret-value-filters-form-and-pagination."""
from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

# ForceDeleteWithoutRecovery because DeleteSecret's minimum recovery window is 7 days and a
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
    resp = sm.create_secret(Name=name, **kwargs)
    ctx.on_cleanup(lambda: _reap_secret(sm, resp["ARN"]))
    return resp


def _refusal(fn):
    """Call fn() and return (Error.Code, Error.Message) from its ClientError.

    An unexpected success raises rather than being reported as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(
        f"expected the call to be refused with a ClientError, but it SUCCEEDED and returned {result!r}"
    )


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


def _digest(text):
    """Short digest for diagnostics -- never put secret material in an assert message."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:16]


CHECK = "batch-get-secret-value-filters-form-and-pagination"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """BatchGetSecretValue's Filters form selects by name prefix, paginates with MaxResults=1 and a
    final page without NextToken, and refuses SecretIdList+Filters and SecretIdList+MaxResults.
    """
    sm = ctx.client("secretsmanager")
    base = ctx.unique_name("sim2real-behav-bgsv-")

    values = {}
    arns = {}
    for suf in ("-a", "-b", "-c"):
        name = base + suf
        values[name] = f"sim2real-not-a-real-secret{suf}"
        created = _create_secret(
            sm,
            ctx,
            name,
            SecretString=values[name],
            Tags=[
                {"Key": "sim2real", "Value": CHECK},
                {"Key": "sim2real:managed", "Value": "true"},
            ],
        )
        arns[name] = created["ARN"]
    expected_names = sorted(values)
    minted_arns = set(arns.values())

    name_filter = [{"Key": "name", "Values": [base]}]

    def _batch_names():
        resp = sm.batch_get_secret_value(Filters=name_filter)
        return sorted(e["Name"] for e in resp.get("SecretValues", []))

    # BatchGetSecretValue is eventually consistent over the secret index.
    settled = _poll(_batch_names, lambda got: got == expected_names)
    assert settled == expected_names, (
        f"the Filters form must converge on exactly the 3 created secrets; "
        f"last observation was {settled}"
    )

    # 1. Value payload and envelope shape.
    resp = sm.batch_get_secret_value(Filters=name_filter)
    entries = {e["Name"]: e for e in resp["SecretValues"]}
    assert set(entries) == set(expected_names), (
        f"the Filters form must return exactly the 3 created secrets by name; "
        f"expected {sorted(expected_names)}, got {sorted(entries)}"
    )
    returned_arns = {e["ARN"] for e in entries.values()}
    assert returned_arns <= minted_arns, (
        "the name filter must not match a secret this check did not create; "
        f"unexpected ARNs {sorted(returned_arns - minted_arns)}"
    )
    for name, entry in entries.items():
        assert _digest(entry["SecretString"]) == _digest(values[name]), (
            f"the batch payload for {name} must match the written value; "
            f"sha256 {_digest(entry['SecretString'])} != {_digest(values[name])}"
        )
        assert entry.get("VersionId"), f"batch entry for {name} must carry VersionId"
        assert entry.get("CreatedDate"), f"batch entry for {name} must carry CreatedDate"
    assert resp.get("Errors", []) == [], (
        f"an all-success batch must report an empty Errors list, got {resp.get('Errors')}"
    )

    # 2. Pagination over the Filters form.
    pages, token, guard = [], None, 0
    while True:
        guard += 1
        assert guard <= 6, "NextToken walk did not terminate within 6 pages for 3 secrets"
        kwargs = {"Filters": name_filter, "MaxResults": 1}
        if token is not None:
            kwargs["NextToken"] = token
        page_resp = sm.batch_get_secret_value(**kwargs)
        page = [e["Name"] for e in page_resp.get("SecretValues", [])]
        assert len(page) <= 1, f"MaxResults=1 must cap the page at one entry, got {page}"
        pages.append(page)
        token = page_resp.get("NextToken")
        if token is None:
            break

    assert "NextToken" not in page_resp, (
        "the final page must OMIT NextToken; a caller looping on its presence "
        f"otherwise never terminates. Final page keys: {sorted(page_resp)}"
    )
    flat = [n for page in pages for n in page]
    assert sorted(flat) == expected_names, (
        f"the pages must partition the 3 matches exactly; walked {pages}"
    )
    assert len(flat) == len(set(flat)), f"a secret appeared on two pages: {pages}"

    # 3a. Both forms at once is a contract violation, not a union.
    code, message = _refusal(
        lambda: sm.batch_get_secret_value(
            SecretIdList=[arns[expected_names[0]]], Filters=name_filter
        )
    )
    assert code == "InvalidParameterException", (
        "SecretIdList and Filters are mutually exclusive and supplying both must be "
        f"refused, got {code}"
    )
    assert message == "You can't specify a secret ID list and filters in the same request.", (
        f"unexpected refusal message for SecretIdList+Filters: {message!r}"
    )

    # 3b. MaxResults is documented as legal only alongside Filters.
    code, message = _refusal(
        lambda: sm.batch_get_secret_value(
            SecretIdList=[arns[n] for n in expected_names], MaxResults=1
        )
    )
    assert code == "InvalidParameterException", (
        "MaxResults requires the Filters form, so combining it with SecretIdList must "
        f"be refused, got {code}"
    )
    assert message == "Max results can only be used with filters.", (
        f"unexpected refusal message for SecretIdList+MaxResults: {message!r}"
    )

    # Control: the SecretIdList form is unaffected and still returns all three.
    ok = sm.batch_get_secret_value(SecretIdList=[arns[n] for n in expected_names])
    assert sorted(e["Name"] for e in ok["SecretValues"]) == expected_names, (
        "after two refusals the SecretIdList form must still return all 3 secrets"
    )
    assert ok.get("Errors", []) == [], (
        f"an all-success SecretIdList batch must report an empty Errors list, got {ok.get('Errors')}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
