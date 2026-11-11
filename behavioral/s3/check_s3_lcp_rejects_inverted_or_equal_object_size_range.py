"""s3-lcp-rejects-inverted-or-equal-object-size-range."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "s3-lcp-rejects-inverted-or-equal-object-size-range"
GROUP = "lifecycle-filters"
SERVICES = ["s3"]

_BASELINE_RULES = [
    {"ID": "baseline", "Status": "Enabled", "Filter": {"Prefix": "keep/"}, "Expiration": {"Days": 10}},
]


def _new_bucket(ctx, s3):
    """Create a uniquely-named bucket and register its teardown; return its name."""
    name = ctx.unique_name("sim2real-behav-lcp-")
    params = {"Bucket": name}
    if ctx.region != "us-east-1":
        params["CreateBucketConfiguration"] = {"LocationConstraint": ctx.region}
    s3.create_bucket(**params)
    ctx.on_cleanup(lambda: _delete_bucket(s3, name))
    return name


def _delete_bucket(s3, bucket: str) -> None:
    try:
        s3.delete_bucket(Bucket=bucket)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "NoSuchBucket":
            raise


def _lifecycle_rules(s3, bucket: str):
    """The bucket's current lifecycle Rules list, or None when no configuration is set."""
    try:
        return s3.get_bucket_lifecycle_configuration(Bucket=bucket)["Rules"]
    except ClientError as exc:
        if exc.response["Error"]["Code"] == "NoSuchLifecycleConfiguration":
            return None
        raise


def _settled(probe, predicate, *, description: str, timeout_s: float = 90.0,
             interval_s: float = 1.0, streak: int = 5):
    """Poll until `streak` consecutive reads satisfy predicate; return the last read.
    Lifecycle reads are eventually consistent and not monotonic, so one matching read is not
    convergence."""
    deadline = time.monotonic() + timeout_s
    run, last = 0, None
    while time.monotonic() < deadline:
        last = probe()
        run = run + 1 if predicate(last) else 0
        if run >= streak:
            return last
        time.sleep(interval_s)
    raise AssertionError(f"{description} not settled within {timeout_s}s. Last read: {last!r}")


def _error(fn):
    """(Error.Code, Error.Message) of the ClientError fn() raises; an unexpected success fails."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """PutBucketLifecycleConfiguration refuses an And filter whose ObjectSizeLessThan does not
    exceed ObjectSizeGreaterThan (inverted or equal), and leaves the prior configuration unchanged.
    """
    s3 = ctx.client("s3")
    bucket = _new_bucket(ctx, s3)

    s3.put_bucket_lifecycle_configuration(
        Bucket=bucket, LifecycleConfiguration={"Rules": _BASELINE_RULES}
    )
    settled = _settled(
        lambda: _lifecycle_rules(s3, bucket),
        lambda rules: rules == _BASELINE_RULES,
        description=f"the baseline configuration on {bucket}",
    )
    assert settled == _BASELINE_RULES, f"baseline did not settle to {_BASELINE_RULES!r}, got {settled!r}"

    expected_message = "'ObjectSizeLessThan' has to be a value greater than 'ObjectSizeGreaterThan'."

    inverted = {
        "Rules": [
            {"ID": "inverted", "Status": "Enabled",
             "Filter": {"And": {"ObjectSizeGreaterThan": 1000, "ObjectSizeLessThan": 100}},
             "Expiration": {"Days": 5}},
        ]
    }
    code, message = _error(
        lambda: s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration=inverted)
    )
    assert code == "InvalidRequest", f"inverted size range got code {code!r}, expected InvalidRequest"
    assert message == expected_message, f"inverted size range message {message!r} != {expected_message!r}"

    rules = _lifecycle_rules(s3, bucket)
    assert rules == _BASELINE_RULES, (
        f"after the rejected inverted-range PUT, lifecycle rules are {rules!r}; "
        f"expected the baseline {_BASELINE_RULES!r} to be unchanged"
    )

    equal_range = {
        "Rules": [
            {"ID": "equalrange", "Status": "Enabled",
             "Filter": {"And": {"ObjectSizeGreaterThan": 1000, "ObjectSizeLessThan": 1000}},
             "Expiration": {"Days": 5}},
        ]
    }
    code, message = _error(
        lambda: s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration=equal_range)
    )
    assert code == "InvalidRequest", f"equal size range got code {code!r}, expected InvalidRequest"
    assert message == expected_message, f"equal size range message {message!r} != {expected_message!r}"

    rules = _lifecycle_rules(s3, bucket)
    assert rules == _BASELINE_RULES, (
        f"after the rejected equal-range PUT, lifecycle rules are {rules!r}; "
        f"expected the baseline {_BASELINE_RULES!r} to be unchanged"
    )

    # Positive control: the same shape with a true gap (100 < 1000) is accepted and replaces the
    # baseline, proving the rejection above was about the range and not the And/size filter itself.
    valid_rules = [
        {"ID": "validrange", "Status": "Enabled",
         "Filter": {"And": {"ObjectSizeGreaterThan": 100, "ObjectSizeLessThan": 1000}},
         "Expiration": {"Days": 5}},
    ]
    s3.put_bucket_lifecycle_configuration(Bucket=bucket, LifecycleConfiguration={"Rules": valid_rules})
    settled = _settled(
        lambda: _lifecycle_rules(s3, bucket),
        lambda rules: rules == valid_rules,
        description=f"the valid-range configuration on {bucket}",
    )
    assert settled == valid_rules, f"valid size range did not settle to {valid_rules!r}, got {settled!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
