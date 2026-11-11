"""ec2-image-datatype-validation-is-asynchronous-and-the-parameter-never-lands."""
from __future__ import annotations

import time
import uuid

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ec2-image-datatype-validation-is-asynchronous-and-the-parameter-never-lands"
GROUP = "server-side"
SERVICES = ["ssm"]

_AL2023_AMI_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"
_AMI_DATA_TYPE = "aws:ec2:image"
_ABSENCE_FLOOR_S = 10.0
_THROTTLE = ("TooManyUpdates", "ThrottlingException", "Throttling")


def _error(fn):
    """Return the ClientError error dict raised by fn, or raise if it unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(
        "the call was expected to be refused but it succeeded; an over-permissive "
        "target must not be able to launder acceptance into a code mismatch"
    )


def _param_name(ctx, suffix=""):
    # DescribeParameters drops the leading '/' of a single-segment name; a >=2 segment
    # name is stored and listed verbatim, so Name-equality assertions hold.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix) + "/param"


def _call_with_retry(fn, codes=_THROTTLE, retries=20, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in codes:
                time.sleep(delay)
                continue
            raise
    raise last


def _poll(probe, predicate, timeout_s, interval_s=3.0, what=""):
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


def _delete_if_present(ssm, name):
    """Teardown for a parameter that is expected never to land."""
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise


def _read(ssm, name):
    """GetParameter, returning the Parameter or the error code as a string."""
    try:
        return ssm.get_parameter(Name=name)["Parameter"]
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")


def _listed_names(ssm, name):
    """The names DescribeParameters reports for an exact-name filter."""
    out = []
    for page in ssm.get_paginator("describe_parameters").paginate(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]
    ):
        out += [p["Name"] for p in page["Parameters"]]
    return sorted(out)


def _bogus_ami():
    """A well-formed AMI id that cannot name a real image."""
    return "ami-" + uuid.uuid4().hex[:17]


@tags(
    "axis:negative-delivery",
    "cap:c1",
    "cap:c5",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """PutParameter with DataType aws:ec2:image and a nonexistent AMI answers 200 but never lands
    (create or overwrite), while the same call with a real AMI lands and is readable.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/parameter-store-ec2-aliases.html
    Reference: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_PutParameter.html
    """

    ssm = ctx.client("ssm")

    # --- the derivation source: a real AMI id, from AWS's own published catalog ---
    catalog = ssm.get_parameter(Name=_AL2023_AMI_PARAM)["Parameter"]
    real_ami = catalog["Value"]
    assert real_ami.startswith("ami-") and len(real_ami) > 12, (
        f"{_AL2023_AMI_PARAM} must resolve to an AMI id; got {real_ami!r}. This check "
        "cannot create a real AMI, so an unresolvable catalog parameter is a FAIL"
    )

    good = _param_name(ctx, "amitype-good-")
    bad = _param_name(ctx, "amitype-bad-")
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=good))
    ctx.on_cleanup(lambda: _delete_if_present(ssm, bad))

    # --- positive control: a real AMI id lands; its latency sizes the absence window ---
    started = time.monotonic()
    put_good = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=good,
            Value=real_ami,
            Type="String",
            DataType=_AMI_DATA_TYPE,
            Tags=[{"Key": "sim2real", "Value": "ami-datatype"}],
        )
    )
    assert put_good["Version"] == 1, (
        f"the first PutParameter for {good} must mint Version 1, got {put_good!r}"
    )
    landed = _poll(
        lambda: _read(ssm, good),
        lambda p: isinstance(p, dict),
        timeout_s=120.0,
        interval_s=3.0,
        what=f"the validated aws:ec2:image parameter {good} becoming readable",
    )
    latency = time.monotonic() - started
    assert landed["Value"] == real_ami, (
        f"the validated parameter must serve the AMI id we stored, expected "
        f"{real_ami!r}, got {landed['Value']!r}"
    )
    assert landed["DataType"] == _AMI_DATA_TYPE, (
        f"GetParameter must echo DataType {_AMI_DATA_TYPE!r} for a validated AMI "
        f"parameter, got {landed.get('DataType')!r}"
    )
    assert _listed_names(ssm, good) == [good], (
        f"DescribeParameters must enumerate the validated parameter {good!r}, got "
        f"{_listed_names(ssm, good)!r}"
    )

    # Validation latency is undocumented, so the absence window scales with the measured
    # positive latency; a target without async validation cannot pass by being slow.
    window = max(3.0 * latency, _ABSENCE_FLOOR_S)

    # --- leg 1: a bogus AMI id is ACCEPTED with a 200 and then never lands -------
    # A synchronous 400 here is also wrong: validation is documented as asynchronous.
    bogus = _bogus_ami()
    put_bad = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=bad,
            Value=bogus,
            Type="String",
            DataType=_AMI_DATA_TYPE,
            Tags=[{"Key": "sim2real", "Value": "ami-datatype"}],
        )
    )
    assert put_bad.get("Version") == 1, (
        "PutParameter with an invalid aws:ec2:image value must still answer 200 with "
        f"Version 1 — the validation is documented as asynchronous — got {put_bad!r}"
    )

    deadline = time.monotonic() + window
    saw = _read(ssm, bad)
    while time.monotonic() < deadline:
        saw = _read(ssm, bad)
        if saw == "ParameterNotFound":
            break
        time.sleep(3.0)
    assert saw == "ParameterNotFound", (
        f"a parameter whose aws:ec2:image value failed validation must not be "
        f"readable; after {window:.0f}s (3x the measured {latency:.0f}s positive "
        f"latency) GetParameter({bad}) returned {saw!r}"
    )
    assert _listed_names(ssm, bad) == [], (
        f"DescribeParameters must not enumerate a parameter that failed aws:ec2:image "
        f"validation, got {_listed_names(ssm, bad)!r}"
    )
    # And a mutation on the name that never landed is refused as not-found, so the
    # name is genuinely absent rather than merely hidden from reads.
    label_error = _error(
        lambda: ssm.label_parameter_version(
            Name=bad, ParameterVersion=1, Labels=["sim2real-never"]
        )
    )
    assert label_error["Code"] == "ParameterNotFound", (
        f"labelling a version of a parameter that failed validation must be refused "
        f"with ParameterNotFound, got {label_error!r}"
    )
    assert label_error["Message"] == f"Parameter {bad} not found.", label_error["Message"]

    # --- leg 2: the same failure on an OVERWRITE leaves the stored bytes alone ----
    _call_with_retry(
        lambda: ssm.put_parameter(
            Name=good,
            Value=_bogus_ami(),
            Type="String",
            DataType=_AMI_DATA_TYPE,
            Overwrite=True,
        )
    )
    # The value must stay at the old bytes for every observation across the window.
    started_hold = time.monotonic()
    observations = 0
    while True:
        elapsed = time.monotonic() - started_hold
        current = _read(ssm, good)
        observations += 1
        assert isinstance(current, dict), (
            f"a failed overwrite must not destroy the parameter; {elapsed:.0f}s after "
            f"the bogus overwrite GetParameter({good}) returned {current!r}"
        )
        assert current["Value"] == real_ami, (
            "an overwrite whose aws:ec2:image value fails validation must leave the "
            f"stored value at {real_ami!r}; {elapsed:.0f}s after the bogus overwrite "
            f"it was {current['Value']!r}"
        )
        if elapsed >= window:
            break
        time.sleep(3.0)
    assert observations >= 2, (
        f"the {window:.0f}s hold must produce at least two observations of the "
        f"unchanged value, got {observations}"
    )

    # --- leg 3: restore — the identical overwrite with a REAL AMI id does land ----
    put_restore = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=good,
            Value=real_ami,
            Type="String",
            DataType=_AMI_DATA_TYPE,
            Overwrite=True,
        )
    )
    restored_version = put_restore["Version"]
    final = _poll(
        lambda: _read(ssm, good),
        lambda p: isinstance(p, dict) and p.get("Version") == restored_version,
        timeout_s=120.0,
        interval_s=3.0,
        what=(
            f"the restoring overwrite of {good} becoming visible as version "
            f"{restored_version}"
        ),
    )
    assert final["Value"] == real_ami, (
        f"the restoring overwrite must serve {real_ami!r}, got {final['Value']!r}"
    )
    assert final["DataType"] == _AMI_DATA_TYPE, (
        f"the restored parameter must still carry DataType {_AMI_DATA_TYPE!r}, got "
        f"{final.get('DataType')!r}"
    )
    # Neither bogus write may have contributed a readable version to history.
    history = []
    for page in ssm.get_paginator("get_parameter_history").paginate(Name=good):
        history += page["Parameters"]
    values = [h["Value"] for h in history]
    assert set(values) == {real_ami}, (
        "every version retained for an aws:ec2:image parameter must carry a validated "
        f"AMI id; history holds {values!r} but only {real_ami!r} ever validated"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
