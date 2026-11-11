"""parameter-version-selector-and-label-move."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-version-selector-and-label-move"
GROUP = 'state-machine'
SERVICES = ['ssm']


# SSM parameter mutation throttles with TooManyUpdates, and GetParameterHistory is not always
# read-your-writes for a just-moved label.
def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"the call was expected to be refused but it succeeded: {result!r}")


def _param_name(ctx, suffix=""):
    # SSM requires a leading '/' for any hierarchical (slash-containing) name.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix)


def _track_parameter(ctx, ssm, name):
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
    return name


def _call_with_retry(fn, retries=10, delay=2.0):
    last = None
    for _ in range(retries):
        try:
            return fn()
        except ClientError as exc:
            last = exc
            if exc.response.get("Error", {}).get("Code") in (
                "TooManyUpdates",
                "ThrottlingException",
            ):
                time.sleep(delay)
                continue
            raise
    raise last


def _poll(probe, predicate, timeout_s=60, interval_s=2.0):
    deadline = time.monotonic() + timeout_s
    last = None
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _labels_for_version(ssm, name, version):
    """The Labels list recorded against one version by GetParameterHistory."""
    for entry in ssm.get_parameter_history(Name=name, MaxResults=50)["Parameters"]:
        if entry["Version"] == version:
            return sorted(entry.get("Labels", []))
    raise AssertionError(f"version {version} absent from GetParameterHistory of {name}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """A version selector resolves that version and echoes it as Selector with the base ARN.

    Moving a label re-points it: the label lands on the new version and leaves the old one.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/userguide/sysman-paramstore-labels.html
    """

    ssm = ctx.client("ssm")

    name = _param_name(ctx, "probe-selector-")
    _track_parameter(ctx, ssm, name)

    v1 = ssm.put_parameter(Name=name, Value="rev-one", Type="String")
    assert v1["Version"] == 1, f"first PutParameter must mint Version 1, got {v1}"
    v2 = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=name, Value="rev-two", Type="String", Overwrite=True
        )
    )
    assert v2["Version"] == 2, f"expected Version 2, got {v2}"
    v3 = _call_with_retry(
        lambda: ssm.put_parameter(
            Name=name, Value="rev-three", Type="String", Overwrite=True
        )
    )
    assert v3["Version"] == 3, f"expected Version 3, got {v3}"

    # --- numeric selector -------------------------------------------------
    base = ssm.get_parameter(Name=name)["Parameter"]
    assert base["Version"] == 3, f"unselected read must return latest, got {base}"
    assert "Selector" not in base, (
        f"an unselected GetParameter must not report a Selector, got {base.get('Selector')!r}"
    )
    base_arn = base["ARN"]

    pinned = ssm.get_parameter(Name=f"{name}:2")["Parameter"]
    assert pinned["Version"] == 2, f"selector ':2' must resolve Version 2, got {pinned}"
    assert pinned["Value"] == "rev-two", f"selector ':2' returned {pinned['Value']!r}"
    assert pinned["Selector"] == ":2", (
        f"GetParameter must echo Selector ':2', got {pinned.get('Selector')!r}"
    )
    assert pinned["Name"] == name, (
        f"the returned Name must be the base name, not the selector form: {pinned['Name']!r}"
    )
    assert pinned["ARN"] == base_arn, (
        f"a selector must not change the ARN: {pinned['ARN']!r} != {base_arn!r}"
    )

    # --- label attach, then label move ------------------------------------
    attach = _call_with_retry(
        lambda: ssm.label_parameter_version(
            Name=name, ParameterVersion=1, Labels=["sim2real-stable"]
        )
    )
    assert attach.get("InvalidLabels", []) == [], (
        f"a conforming label must not come back under InvalidLabels: {attach}"
    )
    assert attach["ParameterVersion"] == 1, attach

    labeled = ssm.get_parameter(Name=f"{name}:sim2real-stable")["Parameter"]
    assert labeled["Version"] == 1, f"label must resolve Version 1, got {labeled}"
    assert labeled["Selector"] == ":sim2real-stable", (
        f"expected Selector ':sim2real-stable', got {labeled.get('Selector')!r}"
    )

    _poll(
        lambda: _labels_for_version(ssm, name, 1),
        lambda got: got == ["sim2real-stable"],
        timeout_s=30,
    )

    moved = _call_with_retry(
        lambda: ssm.label_parameter_version(
            Name=name, ParameterVersion=3, Labels=["sim2real-stable"]
        )
    )
    assert moved.get("InvalidLabels", []) == [], (
        f"moving an existing label to another version must succeed, got {moved}"
    )
    assert moved["ParameterVersion"] == 3, moved

    after = ssm.get_parameter(Name=f"{name}:sim2real-stable")["Parameter"]
    assert after["Version"] == 3, (
        f"after the move the label must resolve Version 3, got {after['Version']}"
    )
    assert after["Value"] == "rev-three", after["Value"]

    # The move must be visible from BOTH ends: gained by v3, lost by v1.
    _poll(
        lambda: (
            _labels_for_version(ssm, name, 1),
            _labels_for_version(ssm, name, 3),
        ),
        lambda got: got == ([], ["sim2real-stable"]),
        timeout_s=30,
    )
    assert _labels_for_version(ssm, name, 1) == [], (
        "moving a label must REMOVE it from the version it was moved off; "
        "an append-only label store leaves it on version 1"
    )

    # Unlabelling a label that is no longer on version 1 must be reported as
    # invalid rather than silently accepted.
    stale = ssm.unlabel_parameter_version(
        Name=name, ParameterVersion=1, Labels=["sim2real-stable"]
    )
    assert stale.get("InvalidLabels", []) == ["sim2real-stable"], (
        "UnlabelParameterVersion on a version that no longer carries the label must "
        f"return it under InvalidLabels, got {stale}"
    )
    assert stale.get("RemovedLabels", []) == [], (
        f"nothing should have been removed from version 1, got {stale}"
    )

    # Control: the label is still on version 3 and still resolves.
    assert (
        ssm.get_parameter(Name=f"{name}:sim2real-stable")["Parameter"]["Version"] == 3
    ), "the stale unlabel must not have disturbed the label on version 3"

    missing_code, missing_message = _error(
        lambda: ssm.get_parameter(Name=f"{name}:sim2real-never-attached")
    )
    assert missing_code == "ParameterVersionNotFound", (
        f"an unresolvable label selector must raise ParameterVersionNotFound, got {missing_code!r}"
    )
    # The message names a top-level parameter without its leading slash.
    assert missing_message == (
        f"Systems Manager could not find a version of {name.lstrip('/')} that has the "
        f"specified label, "
        f"sim2real-never-attached. Verify the parameter label and try again."
    ), missing_message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
