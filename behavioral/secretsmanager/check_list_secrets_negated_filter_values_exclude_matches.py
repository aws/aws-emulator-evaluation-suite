"""list-secrets-negated-filter-values-exclude-matches."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags


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
                f"secret {secret_id} still present {timeout_s}s after ForceDeleteWithoutRecovery"
            )
        time.sleep(interval_s)


def _create_secret(sm, ctx, name, extra_tags=(), **kwargs):
    """Create a secret, register its reaping teardown, and return the raw response."""
    resp = sm.create_secret(
        Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}, *extra_tags], **kwargs
    )
    ctx.on_cleanup(lambda: _reap_secret(sm, resp["ARN"]))
    return resp


def _refusal(fn):
    """Call fn(); return the (Error.Code, Error.Message) it raised; an unexpected success raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message")
    raise AssertionError(f"expected the call to be refused, but it SUCCEEDED and returned {result!r}")


def _poll(probe, predicate, *, timeout_s=150.0, interval_s=3.0):
    """Bounded poll; returns the last observation whether or not the predicate held."""
    deadline = time.monotonic() + timeout_s
    last = probe()
    while not predicate(last):
        if time.monotonic() >= deadline:
            return last
        time.sleep(interval_s)
        last = probe()
    return last


CHECK = "list-secrets-negated-filter-values-exclude-matches"
GROUP = "query"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A ListSecrets filter value prefixed with `!` excludes what the bare value would select, for
    name, tag-key, tag-value and description; a negation intersects with same-filter positive
    values.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_Filter.html
    """
    sm = ctx.client("secretsmanager")
    base = ctx.unique_name("sim2real-behav-lsneg-")
    tier_key = f"{base}-tier"
    names = {s: f"{base}-{s}" for s in ("app-1", "app-2", "db-1")}
    _create_secret(sm, ctx, names["app-1"], [{"Key": tier_key, "Value": "web"}],
                   SecretString="sim2real-not-a-real-secret", Description="Payment gateway credentials")
    _create_secret(sm, ctx, names["app-2"], (),
                   SecretString="sim2real-not-a-real-secret", Description="Reporting database login")
    _create_secret(sm, ctx, names["db-1"], [{"Key": tier_key, "Value": "data"}],
                   SecretString="sim2real-not-a-real-secret")

    # Every query carries a name filter on a prefix only this check can occupy.
    own = {"Key": "name", "Values": [base]}

    def query(*extra):
        out = []
        for page in sm.get_paginator("list_secrets").paginate(Filters=[own, *extra]):
            out.extend(s["Name"] for s in page["SecretList"])
        return sorted(out)

    every = sorted(names.values())
    settled = _poll(lambda: query(), lambda got: got == every)
    assert settled == every, f"the name filter must converge on the 3 created secrets, got {settled}"

    cases = [
        ("negated name prefix in a second filter",
         [{"Key": "name", "Values": [f"!{base}-app"]}], ["db-1"]),
        ("negated name prefix beside the positive value in one filter",
         None, ["db-1"]),
        ("negated tag-key", [{"Key": "tag-key", "Values": [f"!{tier_key}"]}], ["app-2"]),
        ("negated tag-value", [{"Key": "tag-value", "Values": ["!web"]}], ["app-2", "db-1"]),
        ("negated description", [{"Key": "description", "Values": ["!payment"]}], ["app-2", "db-1"]),
        ("positive control: bare tag-key", [{"Key": "tag-key", "Values": [tier_key]}],
         ["app-1", "db-1"]),
    ]
    for label, extra, want_suffixes in cases:
        want = sorted(names[s] for s in want_suffixes)
        if extra is None:
            probe = lambda: sorted(  # noqa: E731
                s["Name"]
                for page in sm.get_paginator("list_secrets").paginate(
                    Filters=[{"Key": "name", "Values": [base, f"!{base}-app"]}])
                for s in page["SecretList"]
            )
        else:
            probe = lambda extra=extra: query(*extra)  # noqa: E731
        got = _poll(probe, lambda g, want=want: g == want)
        assert got == want, f"{label}: must select {want}, got {got}"

    # A value and its own negation in one filter select nothing: the negation intersects.
    contradiction = query({"Key": "tag-key", "Values": [f"!{tier_key}", tier_key]})
    assert contradiction == [], (
        f"tag-key values [!K, K] must select nothing (negation is intersected), got {contradiction}"
    )
    # Negating the whole prefix excludes every secret the positive filter admitted.
    excluded = query({"Key": "name", "Values": [f"!{base}"]})
    assert excluded == [], f"name [!{base!r}] must exclude all 3 secrets, got {excluded}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
