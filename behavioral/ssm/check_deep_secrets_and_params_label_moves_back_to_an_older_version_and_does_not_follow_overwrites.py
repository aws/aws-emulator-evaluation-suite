"""deep-secrets-and-params-label-moves-back-to-an-older-version-and-does-not-follow-overwrites."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-secrets-and-params-label-moves-back-to-an-older-version-and-does-not-follow-overwrites"

GROUP = "versioning"

SERVICES = ["ssm"]

_LABEL = "sim2real-release"


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """LabelParameterVersion moves a label from version 3 back to version 1 without refusal, and the
    label stays pinned to version 1 after a later Overwrite mints version 4.
    """
    ssm = ctx.client("ssm")
    name = f"/{ctx.unique_name('sim2real-deep-ssm-')}/label"
    ctx.on_cleanup(lambda: _delete_parameter(ssm, name))

    for i in (1, 2, 3):
        v = _put(ssm, name, f"rev-{i}", overwrite=i > 1)
        assert v["Version"] == i, f"put #{i} minted Version {v['Version']!r}"

    fwd = ssm.label_parameter_version(Name=name, ParameterVersion=3, Labels=[_LABEL])
    assert fwd.get("InvalidLabels", []) == [] and fwd["ParameterVersion"] == 3, fwd
    at3 = ssm.get_parameter(Name=f"{name}:{_LABEL}")["Parameter"]
    assert (at3["Version"], at3["Value"]) == (3, "rev-3"), (
        f"the label must first resolve version 3, got {at3['Version']!r} {at3['Value']!r}"
    )

    # --- move the label BACKWARDS -----------------------------------------------------------------
    # LabelParameterVersion has no overwrite/force flag; moving a label backwards is a plain call.
    back = ssm.label_parameter_version(Name=name, ParameterVersion=1, Labels=[_LABEL])
    assert back.get("InvalidLabels", []) == [], (
        f"moving a label to an OLDER version must be accepted, got InvalidLabels "
        f"{back.get('InvalidLabels')!r}"
    )
    assert back["ParameterVersion"] == 1, f"the move must report version 1, got {back!r}"

    at1 = ssm.get_parameter(Name=f"{name}:{_LABEL}")["Parameter"]
    assert (at1["Version"], at1["Value"]) == (1, "rev-1"), (
        f"after moving back, the label must resolve version 1 byte-exact, got "
        f"{at1['Version']!r} {at1['Value']!r}"
    )
    assert at1["Selector"] == f":{_LABEL}", f"Selector must echo the label: {at1.get('Selector')!r}"

    labels = _labels_by_version(ssm, name)
    assert labels == {1: [_LABEL], 2: [], 3: []}, (
        f"the label must exist on exactly one version (1) after the backward move: {labels!r}"
    )

    # --- an unrelated later write must not drag the label along -----------------------------------
    v4 = _put(ssm, name, "rev-4", overwrite=True)
    assert v4["Version"] == 4, f"overwrite minted Version {v4['Version']!r}, expected 4"

    unselected = ssm.get_parameter(Name=name)["Parameter"]
    assert (unselected["Version"], unselected["Value"]) == (4, "rev-4"), (
        f"an unselected read must follow latest (4), got {unselected['Version']!r}"
    )
    still = ssm.get_parameter(Name=f"{name}:{_LABEL}")["Parameter"]
    assert (still["Version"], still["Value"]) == (1, "rev-1"), (
        f"a label pins a version: after an Overwrite it must still resolve version 1, got "
        f"{still['Version']!r} {still['Value']!r}"
    )
    labels = _labels_by_version(ssm, name)
    assert labels == {1: [_LABEL], 2: [], 3: [], 4: []}, (
        f"the new version must not inherit the label: {labels!r}"
    )

    # Both selector forms in one batch resolve independently to two different versions.
    batch = ssm.get_parameters(Names=[f"{name}:{_LABEL}", f"{name}:3"])
    got = sorted((p["Selector"], p["Version"], p["Value"]) for p in batch["Parameters"])
    assert got == sorted([(f":{_LABEL}", 1, "rev-1"), (":3", 3, "rev-3")]), (
        f"GetParameters must resolve the label and the version selector independently: {got!r}; "
        f"invalid={batch.get('InvalidParameters')!r}"
    )


def _put(ssm, name: str, value: str, *, overwrite: bool):
    deadline = time.monotonic() + 60.0
    while True:
        try:
            return ssm.put_parameter(Name=name, Value=value, Type="String", Overwrite=overwrite)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ThrottlingException", "TooManyUpdates") and time.monotonic() < deadline:
                time.sleep(1.0)
                continue
            raise


def _labels_by_version(ssm, name: str) -> dict[int, list[str]]:
    out: dict[int, list[str]] = {}
    for page in ssm.get_paginator("get_parameter_history").paginate(Name=name):
        for p in page["Parameters"]:
            out[p["Version"]] = sorted(p.get("Labels", []))
    return out


def _delete_parameter(ssm, name: str) -> None:
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise RuntimeError(f"delete_parameter({name}): {exc}") from exc


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
