"""list-secrets-description-and-all-filters-match-words-case-insensitively."""
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
    """Call fn(); return the (Error.Code, Error.Message) it raised. An unexpected success raises."""
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


CHECK = "list-secrets-description-and-all-filters-match-words-case-insensitively"
GROUP = "query"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSecrets `description` matches a case-insensitive prefix of any description word, `all`
    searches name words, description, tag keys and values case-insensitively and ANDs the words
    of one value, while `name` stays case-sensitive."""
    sm = ctx.client("secretsmanager")
    base = ctx.unique_name("sim2real-behav-lsall-")
    tier_key = f"{base}-tier"
    names = {s: f"{base}-{s}" for s in ("app-1", "app-2", "db-1")}
    _create_secret(sm, ctx, names["app-1"], [{"Key": tier_key, "Value": "web"}],
                   SecretString="sim2real-not-a-real-secret", Description="Payment gateway credentials")
    _create_secret(sm, ctx, names["app-2"], (),
                   SecretString="sim2real-not-a-real-secret", Description="reporting Database login")
    _create_secret(sm, ctx, names["db-1"], [{"Key": tier_key, "Value": "data"}],
                   SecretString="sim2real-not-a-real-secret")

    # Every query is scoped by a name prefix only this check's secrets carry.
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
        ("description, first word as written", "description", "Payment", ["app-1"]),
        ("description, first word lower-cased", "description", "payment", ["app-1"]),
        ("description, a later word", "description", "gateway", ["app-1"]),
        ("description, upper-cased later word", "description", "DATABASE", ["app-2"]),
        ("description, word prefix", "description", "cred", ["app-1"]),
        ("all, description word", "all", "gateway", ["app-1"]),
        ("all, upper-cased description word", "all", "GATEWAY", ["app-1"]),
        ("all, tag value", "all", "web", ["app-1"]),
        ("all, tag key", "all", tier_key, ["app-1", "db-1"]),
        ("all, prefix of a description word and of a tag value", "all", "data", ["app-2", "db-1"]),
        ("all, name word", "all", "db", ["db-1"]),
    ]
    for label, key, value, want_suffixes in cases:
        want = sorted(names[s] for s in want_suffixes)
        got = _poll(lambda key=key, value=value: query({"Key": key, "Values": [value]}),
                    lambda g, want=want: g == want)
        assert got == want, f"{label}: {key}={value!r} must select {want}, got {got}"

    # Asserted after every positive case converged, so an empty answer is not index lag.
    both_words = query({"Key": "all", "Values": ["payment login"]})
    assert both_words == [], (
        f"all='payment login' ANDs its words and no secret carries both, got {both_words}"
    )
    upper_name = query({"Key": "description", "Values": ["Payment"]},
                       {"Key": "name", "Values": [base.upper()]})
    assert upper_name == [], f"name is case-sensitive; {base.upper()!r} selected {upper_name}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
