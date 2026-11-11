"""list-secrets-tag-key-and-tag-value-filters-prefix-match-and-combine."""
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


def _create_secret(sm, ctx, name, extra_tags, **kwargs):
    """Create a secret, register its reaping teardown, and return the raw response."""
    resp = sm.create_secret(
        Name=name, Tags=[{"Key": "sim2real", "Value": CHECK}, *extra_tags], **kwargs
    )
    ctx.on_cleanup(lambda: _reap_secret(sm, resp["ARN"]))
    return resp


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


CHECK = "list-secrets-tag-key-and-tag-value-filters-prefix-match-and-combine"
GROUP = "query"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListSecrets tag-key / tag-value filters are case-sensitive prefix matches; values in one
    filter OR together, separate filters AND together, and tag-key and tag-value may match different
    tags.

    Reference: https://docs.aws.amazon.com/secretsmanager/latest/apireference/API_Filter.html
    """
    sm = ctx.client("secretsmanager")
    base = ctx.unique_name("sim2real-behav-lstag-")
    env_key = f"{base}-env"
    team_key = f"{base}-team"

    names = {s: f"{base}-{s}" for s in ("a", "b", "c")}
    _create_secret(sm, ctx, names["a"], [{"Key": env_key, "Value": "alpha-one"}],
                   SecretString="sim2real-not-a-real-secret-a")
    _create_secret(sm, ctx, names["b"],
                   [{"Key": env_key, "Value": "beta-two"}, {"Key": team_key, "Value": "alpha-x"}],
                   SecretString="sim2real-not-a-real-secret-b")
    _create_secret(sm, ctx, names["c"], [{"Key": team_key, "Value": "gamma"}],
                   SecretString="sim2real-not-a-real-secret-c")

    def query(*extra):
        # The name filter scopes every query to a prefix only this check can occupy.
        filters = [{"Key": "name", "Values": [base]}, *extra]
        out = []
        for page in sm.get_paginator("list_secrets").paginate(Filters=filters):
            out.extend(s["Name"] for s in page["SecretList"])
        return sorted(out)

    every = sorted(names.values())
    settled = _poll(lambda: query(), lambda got: got == every)
    assert settled == every, (
        f"the name filter {base!r} must converge on exactly the 3 created secrets, got {settled}"
    )

    cases = [
        ("tag-key exact", [{"Key": "tag-key", "Values": [env_key]}], ["a", "b"]),
        ("tag-key prefix", [{"Key": "tag-key", "Values": [f"{base}-en"]}], ["a", "b"]),
        ("tag-key prefix covering both keys", [{"Key": "tag-key", "Values": [f"{base}-"]}],
         ["a", "b", "c"]),
        ("tag-key two values OR", [{"Key": "tag-key", "Values": [team_key, env_key]}],
         ["a", "b", "c"]),
        ("tag-value prefix", [{"Key": "tag-value", "Values": ["alpha"]}], ["a", "b"]),
        ("tag-value exact", [{"Key": "tag-value", "Values": ["gamma"]}], ["c"]),
        ("tag-key AND tag-value on the same tag",
         [{"Key": "tag-key", "Values": [team_key]}, {"Key": "tag-value", "Values": ["alpha"]}],
         ["b"]),
        ("tag-key AND tag-value satisfied by different tags",
         [{"Key": "tag-key", "Values": [team_key]}, {"Key": "tag-value", "Values": ["beta"]}],
         ["b"]),
    ]
    for label, extra, want_suffixes in cases:
        want = sorted(names[s] for s in want_suffixes)
        got = _poll(lambda extra=extra: query(*extra), lambda g, want=want: g == want)
        assert got == want, f"{label}: filters {extra!r} must select {want}, got {got}"

    # Case sensitivity: an upper-cased key or value prefix selects nothing of ours. Asserted
    # only after every positive case above has converged, so an empty answer is not lag.
    upper_key = query({"Key": "tag-key", "Values": [env_key.upper()]})
    assert upper_key == [], f"tag-key is case-sensitive; {env_key.upper()!r} selected {upper_key}"
    upper_value = query({"Key": "tag-value", "Values": ["ALPHA"]})
    assert upper_value == [], f"tag-value is case-sensitive; 'ALPHA' selected {upper_value}"
    mid_value = query({"Key": "tag-value", "Values": ["one"]})
    assert mid_value == [], f"tag-value is a prefix match, not substring; 'one' selected {mid_value}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
