"""parameter-last-modified-user-is-the-live-sts-session-identity."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-last-modified-user-is-the-live-sts-session-identity"
GROUP = "cross-service"
SERVICES = ["ssm", "sts"]

_THROTTLE = ("TooManyUpdates", "ThrottlingException", "Throttling")


def _param_name(ctx, suffix=""):
    # SSM requires a leading '/' for any hierarchical (slash-containing) name.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix)


def _call_with_retry(fn, retries=15, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in _THROTTLE:
                time.sleep(delay)
                continue
            raise
    raise last


def _poll(probe, predicate, timeout_s=60.0, interval_s=2.0, what=""):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{what or 'condition'} not met within {timeout_s}s "
                f"(last observed: {last!r})"
            )
        time.sleep(interval_s)


def _metadata(ssm, name):
    """The single ParameterMetadata DescribeParameters reports for an exact name."""
    found = []
    for page in ssm.get_paginator("describe_parameters").paginate(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]
    ):
        found += page["Parameters"]
    assert len(found) == 1, (
        f"DescribeParameters must report exactly one metadata row for {name!r}, got "
        f"{found!r}"
    )
    return found[0]


def _history(ssm, name):
    out = []
    for page in ssm.get_paginator("get_parameter_history").paginate(Name=name):
        out += page["Parameters"]
    return out


@tags(
    "axis:happy-path",
    "cap:c1",
    "concern:representation",
    "plane:control",
)
def run(ctx) -> None:
    """Every parameter version records as LastModifiedUser the exact ARN STS reports for the writing
    session, and a second parameter from the same session records the same ARN.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_ParameterMetadata.html
    """

    ssm = ctx.client("ssm")
    sts = ctx.client("sts")

    # The expected writer is derived from STS in the same run, never pinned.
    identity = sts.get_caller_identity()
    caller_arn = identity["Arn"]
    account = identity["Account"]
    assert caller_arn.startswith("arn:"), (
        f"GetCallerIdentity must report an ARN for the replaying session, got "
        f"{caller_arn!r}"
    )
    assert account and account.isdigit() and len(account) == 12, (
        f"GetCallerIdentity must report a 12-digit account id, got {account!r}"
    )
    assert account in caller_arn, (
        f"the caller ARN {caller_arn!r} must name the account {account!r} that "
        "GetCallerIdentity reported for the same session"
    )

    first = _param_name(ctx, "lastwriter-a-")
    second = _param_name(ctx, "lastwriter-b-")
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=first))
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=second))

    for version, value in ((1, "writer-one"), (2, "writer-two"), (3, "writer-three")):
        put = _call_with_retry(
            lambda v=value, n=version: ssm.put_parameter(
                Name=first,
                Value=v,
                Type="String",
                Overwrite=n > 1,
                **(
                    {"Tags": [{"Key": "sim2real", "Value": "last-modified-user"}]}
                    if n == 1
                    else {}
                ),
            )
        )
        assert put["Version"] == version, (
            f"PutParameter #{version} must mint Version {version}, got {put!r}"
        )

    # DescribeParameters is a query API, not documented as read-your-writes, so it is polled.
    meta = _poll(
        lambda: _metadata(ssm, first),
        lambda m: m.get("Version") == 3,
        what=f"DescribeParameters catching up to version 3 of {first}",
    )
    recorded = meta.get("LastModifiedUser")
    assert recorded, (
        "DescribeParameters must record who last changed the parameter; "
        f"LastModifiedUser was {recorded!r} on {meta!r}"
    )
    # Holds for both the session and role ARN forms, and catches a placeholder account.
    assert account in recorded, (
        f"the recorded writer {recorded!r} must name the live account {account!r} that "
        "STS reported for this session; a hardcoded placeholder account fails here"
    )
    assert recorded == caller_arn, (
        f"LastModifiedUser must be the exact ARN STS reports for the writing session; "
        f"expected {caller_arn!r}, got {recorded!r}"
    )

    # GetParameterHistory carries a per-version LastModifiedUser.
    history = _poll(
        lambda: _history(ssm, first),
        lambda h: len(h) == 3,
        what=f"all three versions of {first} appearing in GetParameterHistory",
    )
    writers = {h["Version"]: h.get("LastModifiedUser") for h in history}
    assert sorted(writers) == [1, 2, 3], (
        f"GetParameterHistory must report versions 1, 2 and 3, got {sorted(writers)!r}"
    )
    assert set(writers.values()) == {caller_arn}, (
        "every version written by one session must record that session as its writer; "
        f"expected every entry to be {caller_arn!r}, got {writers!r}"
    )

    # A second parameter from the same session rules out a value derived from the name.
    _call_with_retry(
        lambda: ssm.put_parameter(
            Name=second,
            Value="writer-other",
            Type="String",
            Tags=[{"Key": "sim2real", "Value": "last-modified-user"}],
        )
    )
    other = _poll(
        lambda: _metadata(ssm, second),
        lambda m: m.get("Version") == 1,
        what=f"DescribeParameters reporting {second}",
    )
    assert other.get("LastModifiedUser") == recorded, (
        "two parameters written by the same session must record the same writer, so "
        "the value cannot be derived from the parameter name; "
        f"{first} recorded {recorded!r} and {second} recorded "
        f"{other.get('LastModifiedUser')!r}"
    )

    assert other["LastModifiedDate"] >= meta["LastModifiedDate"], (
        f"{second} was written after {first}, so its LastModifiedDate must not be "
        f"earlier; got {other['LastModifiedDate']!r} vs {meta['LastModifiedDate']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
