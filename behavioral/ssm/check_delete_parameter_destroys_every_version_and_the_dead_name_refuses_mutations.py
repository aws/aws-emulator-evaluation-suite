"""delete-parameter-destroys-every-version-and-the-dead-name-refuses-mutations."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-parameter-destroys-every-version-and-the-dead-name-refuses-mutations"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_LABEL = "sim2real-doomed"
_THROTTLE = ("TooManyUpdates", "ThrottlingException", "Throttling")


def _refusal(fn):
    """(code, message) of the ClientError fn raises (asserting an HTTP 4xx); RAISES on success."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        status = exc.response.get("ResponseMetadata", {}).get("HTTPStatusCode")
        assert isinstance(status, int) and 400 <= status < 500, f"expected HTTP 4xx with {err!r}, got {status!r}"
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"the call was expected to be refused but it succeeded: {result!r}")


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


def _read(ssm, name):
    """The (code, message) GetParameter raises for a name, or the resolved Parameter."""
    try:
        return ssm.get_parameter(Name=name)["Parameter"]
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")


def _history(ssm, name):
    out = []
    for page in ssm.get_paginator("get_parameter_history").paginate(Name=name):
        out += page["Parameters"]
    return out


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteParameter destroys every version and label, mutations on the dead name are refused,
    and a recreated parameter has a history of exactly its one new version.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DeleteParameter.html
    """

    ssm = ctx.client("ssm")

    name = _param_name(ctx, "delete-versions-")
    # Registered up front: the last leg recreates the name, so cleanup has work to do
    # whether the check completes or fails partway.
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))

    # Three versions with a label on version 2, so the delete must reach a labelled,
    # non-latest version and not just the head.
    values = {}
    for version, value in ((1, "doomed-one"), (2, "doomed-two"), (3, "doomed-three")):
        put = _call_with_retry(
            lambda v=value, n=version: ssm.put_parameter(
                Name=name,
                Value=v,
                Type="String",
                Overwrite=n > 1,
                **(
                    {"Tags": [{"Key": "sim2real", "Value": "delete-versions"}]}
                    if n == 1
                    else {}
                ),
            )
        )
        assert put["Version"] == version, (
            f"PutParameter #{version} must mint Version {version}, got {put!r}"
        )
        values[version] = value

    labelled = _call_with_retry(
        lambda: ssm.label_parameter_version(
            Name=name, ParameterVersion=2, Labels=[_LABEL]
        )
    )
    assert labelled.get("InvalidLabels", []) == [], (
        f"a conforming label must not come back under InvalidLabels, got {labelled!r}"
    )

    # --- every selector must resolve BEFORE the delete: without this, the ---------
    # post-delete absences would also hold against a target with no selectors at all.
    for version, value in values.items():
        pinned = _poll(
            lambda v=version: _read(ssm, f"{name}:{v}"),
            lambda p: isinstance(p, dict),
            what=f"the pre-delete selector {name}:{version} resolving",
        )
        assert pinned["Value"] == value, (
            f"before the delete, {name}:{version} must serve {value!r}, got "
            f"{pinned['Value']!r}"
        )
    by_label = _poll(
        lambda: _read(ssm, f"{name}:{_LABEL}"),
        lambda p: isinstance(p, dict),
        what=f"the pre-delete label selector {name}:{_LABEL} resolving",
    )
    assert by_label["Version"] == 2, (
        f"before the delete, the label must resolve version 2, got {by_label!r}"
    )
    assert len(_history(ssm, name)) == 3, (
        f"three PutParameter calls must leave three history entries, got "
        f"{[h['Version'] for h in _history(ssm, name)]!r}"
    )

    ssm.delete_parameter(Name=name)

    plain = _poll(
        lambda: _read(ssm, name),
        lambda r: isinstance(r, tuple) and r[0] == "ParameterNotFound",
        what=f"GetParameter({name}) converging to ParameterNotFound",
    )
    # AWS answers a missing parameter ParameterNotFound with an empty message.
    gone = ("ParameterNotFound", "")
    assert plain == gone, f"after the delete GetParameter({name}) must return {gone}, got {plain!r}"
    got = _refusal(lambda: ssm.get_parameter(Name=name))
    assert got == gone, f"GetParameter({name}) after the delete: expected {gone}, got {got!r}"
    # DescribeParameters is eventually consistent, so absence is a bounded poll.
    deadline = time.monotonic() + 60.0
    while True:
        described = [
            p["Name"]
            for page in ssm.get_paginator("describe_parameters").paginate(
                ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]
            )
            for p in page.get("Parameters", [])
        ]
        if described == [] or time.monotonic() >= deadline:
            break
        time.sleep(2.0)
    assert described == [], (
        f"DescribeParameters filtered to Name Equals {name} must return [] after the delete, "
        f"got {described!r}"
    )

    # The parameter itself is gone, so a dead selector is ParameterNotFound, not the
    # ParameterVersionNotFound a live parameter returns for an unknown version.
    for version in sorted(values):
        got = _poll(
            lambda v=version: _read(ssm, f"{name}:{v}"),
            lambda r: isinstance(r, tuple),
            what=f"the selector {name}:{version} ceasing to resolve",
        )
        assert got == gone, (
            f"DeleteParameter must destroy EVERY version, not just the latest; "
            f"{name}:{version} returned {got!r} and must return {gone}"
        )
    label_after = _read(ssm, f"{name}:{_LABEL}")
    assert label_after == gone, (
        f"the label on the deleted parameter must not resolve either; "
        f"{name}:{_LABEL} returned {label_after!r}"
    )
    history = _refusal(lambda: ssm.get_parameter_history(Name=name))
    assert history == gone, (
        f"GetParameterHistory on a deleted parameter must be refused with {gone}, got {history!r}"
    )

    # Mutations on the dead name are refused too, not just reads.
    relabel = _refusal(
        lambda: ssm.label_parameter_version(
            Name=name, ParameterVersion=2, Labels=["sim2real-after-death"]
        )
    )
    relabel_gone = ("ParameterNotFound", f"Parameter {name} not found.")
    assert relabel == relabel_gone, (
        f"labelling a version of a deleted parameter must be refused with {relabel_gone}, got {relabel!r}"
    )
    double_delete = _refusal(lambda: ssm.delete_parameter(Name=name))
    assert double_delete == gone, (
        f"a second DeleteParameter must be refused rather than reported as success, "
        f"got {double_delete!r}"
    )

    # Whether the recreated version counter restarts at 1 is undocumented, so the check reads
    # the version the history reports instead of pinning a number.
    recreated = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=name,
            Value="reborn",
            Type="String",
            Tags=[{"Key": "sim2real", "Value": "delete-versions"}],
        )
    )
    fresh = _poll(
        lambda: _history(ssm, name),
        lambda h: len(h) >= 1,
        what=f"the recreated {name} showing history",
    )
    assert len(fresh) == 1, (
        "a recreated parameter must carry no history from before the delete; "
        f"GetParameterHistory reports versions {[h['Version'] for h in fresh]!r}"
    )
    new_version = fresh[0]["Version"]
    assert new_version == recreated["Version"], (
        f"the history's only entry must be the version PutParameter reported "
        f"({recreated['Version']}), got {new_version}"
    )
    assert fresh[0]["Value"] == "reborn", (
        f"the recreated parameter's only version must hold the new bytes, got "
        f"{fresh[0]['Value']!r}"
    )
    assert fresh[0].get("Labels", []) == [], (
        f"the label from before the delete must not have survived onto the recreated "
        f"parameter, got {fresh[0].get('Labels')!r}"
    )
    reborn = _read(ssm, f"{name}:{new_version}")
    assert isinstance(reborn, dict) and reborn["Value"] == "reborn", (
        f"the recreated parameter's own version selector {name}:{new_version} must "
        f"serve the new bytes, got {reborn!r}"
    )
    # The parameter exists again, so an unknown pre-delete version is now
    # ParameterVersionNotFound.
    for version in sorted(set(values) - {new_version}):
        stale = _read(ssm, f"{name}:{version}")
        # The message names the parameter without its leading '/'.
        expected = (
            "ParameterVersionNotFound",
            f"Systems Manager could not find version {version} of {name.lstrip('/')}. "
            "Verify the version and try again.",
        )
        assert stale == expected, (
            f"after the recreate, the pre-delete version {version} must not resolve; "
            f"{name}:{version} returned {stale!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
