"""deep-secrets-and-params-parameter-version-ceiling-evicts-oldest-and-labelled-oldest-rejected."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "deep-secrets-and-params-parameter-version-ceiling-evicts-oldest-and-labelled-oldest-rejected"

GROUP = "versioning"

SERVICES = ["ssm"]

# Parameter Store keeps at most 100 versions of a parameter. This is a fixed service constant
# (not a Service Quotas value AWS would raise for one account), so it is safe to write down.
_CEILING = 100
_PIN = "sim2real-pinned"


@tags(
    "axis:rejection",
    "cap:c2",
    "concern:data-plane",
    "concern:negative-classes",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """At the 100-version ceiling an Overwrite evicts the oldest version, but is refused with
    ParameterMaxVersionLimitExceeded (no change) while the oldest version carries a label.
    """
    ssm = ctx.client("ssm")
    name = f"/{ctx.unique_name('sim2real-deep-ssm-')}/ceiling"
    ctx.on_cleanup(lambda: _delete_parameter(ssm, name))

    # --- fill the version store to the ceiling -------------------------------------------------
    for i in range(1, _CEILING + 1):
        resp = _put(ssm, name, f"value-{i}", overwrite=i > 1)
        assert resp["Version"] == i, f"put #{i} minted Version {resp['Version']!r}, expected {i}"

    history = _history(ssm, name)
    assert sorted(history) == list(range(1, _CEILING + 1)), (
        f"after {_CEILING} writes the history must hold exactly versions 1..{_CEILING}, got "
        f"{sorted(history)[:3]!r}..{sorted(history)[-3:]!r} ({len(history)} versions)"
    )

    # --- pin the oldest version with a label ----------------------------------------------------
    pinned = ssm.label_parameter_version(Name=name, ParameterVersion=1, Labels=[_PIN])
    assert pinned.get("InvalidLabels", []) == [] and pinned["ParameterVersion"] == 1, (
        f"labelling version 1 must succeed cleanly, got {pinned!r}"
    )

    code, message = _error(lambda: _put(ssm, name, "value-refused", overwrite=True))
    assert code == "ParameterMaxVersionLimitExceeded", (
        f"an Overwrite at the {_CEILING}-version ceiling whose oldest version is labelled must be "
        f"refused with ParameterMaxVersionLimitExceeded, got {code!r}"
    )
    assert message == _max_version_message(name, 1), message

    # Effect absent: no version was minted, none was evicted, the latest value is unchanged.
    history = _history(ssm, name)
    assert sorted(history) == list(range(1, _CEILING + 1)), (
        f"a refused write must neither mint nor evict a version; history is now "
        f"{sorted(history)[:3]!r}..{sorted(history)[-3:]!r} ({len(history)} versions)"
    )
    latest = ssm.get_parameter(Name=name)["Parameter"]
    assert (latest["Version"], latest["Value"]) == (_CEILING, f"value-{_CEILING}"), (
        f"the refused write changed the latest version: {latest['Version']!r} "
        f"{latest['Value']!r}"
    )
    oldest = ssm.get_parameter(Name=f"{name}:1")["Parameter"]
    assert oldest["Value"] == "value-1", (
        f"the pinned oldest version must still serve its value, got {oldest['Value']!r}"
    )

    # --- positive control: move the label to version 2; version 1 is now evictable -------------
    moved = ssm.label_parameter_version(Name=name, ParameterVersion=2, Labels=[_PIN])
    assert moved.get("InvalidLabels", []) == [] and moved["ParameterVersion"] == 2, moved

    admitted = _put(ssm, name, "value-101", overwrite=True)
    assert admitted["Version"] == _CEILING + 1, (
        f"with the oldest version unlabelled the Overwrite must succeed as Version "
        f"{_CEILING + 1}, got {admitted['Version']!r}"
    )
    history = _history(ssm, name)
    assert sorted(history) == list(range(2, _CEILING + 2)), (
        f"the write must evict exactly version 1 and keep 2..{_CEILING + 1}; got "
        f"{sorted(history)[:3]!r}..{sorted(history)[-3:]!r} ({len(history)} versions)"
    )
    evicted, evicted_message = _error(lambda: ssm.get_parameter(Name=f"{name}:1"))
    assert evicted == "ParameterVersionNotFound", (
        f"the evicted version 1 must be unreadable by selector, got {evicted!r}"
    )
    assert evicted_message == (
        f"Systems Manager could not find version 1 of {name}. Verify the version and try again."
    ), evicted_message
    by_label = ssm.get_parameter(Name=f"{name}:{_PIN}")["Parameter"]
    assert (by_label["Version"], by_label["Value"]) == (2, "value-2"), (
        f"the moved label must resolve version 2 byte-exact, got {by_label['Version']!r} "
        f"{by_label['Value']!r}"
    )

    # --- "oldest" is recomputed: version 2 is now oldest AND labelled, so the next write blocks --
    code, message = _error(lambda: _put(ssm, name, "value-refused-again", overwrite=True))
    assert code == "ParameterMaxVersionLimitExceeded", (
        f"version 2 is now the oldest and carries {_PIN!r}; the next Overwrite must be refused "
        f"with ParameterMaxVersionLimitExceeded, got {code!r}"
    )
    assert message == _max_version_message(name, 2), message
    assert ssm.get_parameter(Name=name)["Parameter"]["Version"] == _CEILING + 1, (
        "a refused write must not advance the latest version"
    )

    removed = ssm.unlabel_parameter_version(Name=name, ParameterVersion=2, Labels=[_PIN])
    assert removed.get("RemovedLabels") == [_PIN], f"unlabel must remove {_PIN!r}: {removed!r}"
    final = _put(ssm, name, "value-102", overwrite=True)
    assert final["Version"] == _CEILING + 2, (
        f"with no label on the oldest version the Overwrite must succeed as Version "
        f"{_CEILING + 2}, got {final['Version']!r}"
    )
    history = _history(ssm, name)
    assert sorted(history) == list(range(3, _CEILING + 3)), (
        f"the second eviction must remove exactly version 2; got "
        f"{sorted(history)[:3]!r}..{sorted(history)[-3:]!r} ({len(history)} versions)"
    )
    assert history[_CEILING + 2] == "value-102" and history[3] == "value-3", (
        f"surviving versions must keep their exact values: v3={history.get(3)!r} "
        f"v{_CEILING + 2}={history.get(_CEILING + 2)!r}"
    )


def _error(fn) -> tuple[str, str]:
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", "<no code>"), err.get("Message") or ""
    raise AssertionError(f"the call was expected to be refused but SUCCEEDED: {result!r}")


def _max_version_message(name: str, oldest: int) -> str:
    # AWS names the parameter without its leading slash here, and the apostrophe is U+2019.
    return (
        f"You attempted to create a new version of {name.lstrip('/')} by calling the "
        f"PutParameter API with the overwrite flag. Version {oldest}, the oldest version, "
        f"can\u2019t be deleted because it has a label associated with it. Move the label to "
        f"another version of the parameter, and try again."
    )


def _put(ssm, name: str, value: str, *, overwrite: bool):
    # PutParameter has a low default TPS; retry only on throttling, never on a semantic error.
    deadline = time.monotonic() + 120.0
    while True:
        try:
            return ssm.put_parameter(Name=name, Value=value, Type="String", Overwrite=overwrite)
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code in ("ThrottlingException", "TooManyUpdates") and time.monotonic() < deadline:
                time.sleep(1.0)
                continue
            raise


def _history(ssm, name: str) -> dict[int, str]:
    out: dict[int, str] = {}
    for page in ssm.get_paginator("get_parameter_history").paginate(Name=name):
        for p in page["Parameters"]:
            out[p["Version"]] = p["Value"]
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
