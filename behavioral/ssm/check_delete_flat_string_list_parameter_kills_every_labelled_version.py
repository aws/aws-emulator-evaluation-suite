"""delete-flat-string-list-parameter-kills-every-labelled-version."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-flat-string-list-parameter-kills-every-labelled-version"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_FIRST_LABEL = "sim2real-first"
_SECOND_LABEL = "sim2real-second"
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


def _poll(probe, predicate, timeout_s=30.0, interval_s=2.0, what=""):
    """probe() once predicate(answer) holds, or its last answer at the deadline; the caller's exact
    assertion then grades that last answer (``what`` names the condition for readers).
    """
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last) or time.monotonic() >= deadline:
            return last
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


def _delete_if_present(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteParameter on a flat-named StringList with a label on each of its two versions
    destroys both versions and both labels; the dead name refuses relabelling, and a String
    recreated under it carries one version, its own type and no label.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DeleteParameter.html
    """
    ssm = ctx.client("ssm")
    # A flat name (no '/'): SSM stores and echoes it bare.
    name = ctx.unique_name("sim2real-behav-flat-list-")
    ctx.on_cleanup(lambda: _delete_if_present(ssm, name))

    values = {1: "alpha,beta", 2: "gamma,delta,epsilon"}
    for version, value in values.items():
        put = _call_with_retry(
            lambda v=value, n=version: ssm.put_parameter(Name=name, Value=v, Type="StringList", Overwrite=n > 1)
        )
        assert put["Version"] == version, f"PutParameter #{version} must mint Version {version}, got {put!r}"
    for version, label in ((1, _FIRST_LABEL), (2, _SECOND_LABEL)):
        labelled = _call_with_retry(
            lambda v=version, lb=label: ssm.label_parameter_version(Name=name, ParameterVersion=v, Labels=[lb])
        )
        assert labelled.get("InvalidLabels", []) == [], f"label {label} on version {version}: {labelled!r}"

    # Every selector resolves before the delete, so the absences below are not vacuous.
    for selector, version in ((f"{name}:1", 1), (f"{name}:2", 2), (f"{name}:{_FIRST_LABEL}", 1),
                              (f"{name}:{_SECOND_LABEL}", 2)):
        got = _poll(lambda s=selector: _read(ssm, s), lambda p: isinstance(p, dict),
                    what=f"the selector {selector} resolving")
        assert isinstance(got, dict) and (got["Version"], got["Value"], got["Type"]) == (
            version, values[version], "StringList"
        ), (
            f"{selector} must serve version {version} {values[version]!r} as StringList, got {got!r}"
        )

    ssm.delete_parameter(Name=name)

    gone = ("ParameterNotFound", "")
    plain = _poll(lambda: _read(ssm, name), lambda r: isinstance(r, tuple),
                  what=f"GetParameter({name}) ceasing to resolve")
    assert plain == gone, f"after the delete GetParameter({name}) must return {gone}, got {plain!r}"
    for selector in (f"{name}:1", f"{name}:2", f"{name}:{_FIRST_LABEL}", f"{name}:{_SECOND_LABEL}"):
        got = _poll(lambda s=selector: _read(ssm, s), lambda r: isinstance(r, tuple),
                    what=f"the selector {selector} ceasing to resolve")
        assert got == gone, f"{selector} on the deleted parameter must return {gone}, got {got!r}"
    history = _refusal(lambda: ssm.get_parameter_history(Name=name))
    assert history == gone, f"GetParameterHistory on the deleted parameter: expected {gone}, got {history!r}"
    relabel = _refusal(lambda: ssm.label_parameter_version(Name=name, ParameterVersion=1, Labels=[_FIRST_LABEL]))
    assert relabel == ("ParameterNotFound", f"Parameter {name} not found."), (
        f"labelling version 1 of the deleted flat-named parameter: got {relabel!r}"
    )

    recreated = _call_with_retry(lambda: ssm.put_parameter(Name=name, Value="reborn", Type="String"))
    fresh = _poll(lambda: _history(ssm, name), lambda h: len(h) >= 1, what=f"the recreated {name} showing history")
    assert [(h["Version"], h["Value"], h["Type"], h.get("Labels", [])) for h in fresh] == [
        (recreated["Version"], "reborn", "String", [])
    ], f"the recreated parameter must have one String version with no labels, got {fresh!r}"
    for label in (_FIRST_LABEL, _SECOND_LABEL):
        got = _read(ssm, f"{name}:{label}")
        assert got == ("ParameterVersionNotFound",
                       f"Systems Manager could not find a version of {name} that has the specified label, "
                       f"{label}. Verify the parameter label and try again."), (
            f"the pre-delete label {label} must not resolve on the recreated parameter, got {got!r}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
