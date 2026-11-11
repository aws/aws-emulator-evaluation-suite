"""delete-parameters-batch-kills-every-version-and-label-for-batch-reads."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "delete-parameters-batch-kills-every-version-and-label-for-batch-reads"
GROUP = "error-semantics"
SERVICES = ["ssm"]

_LABEL = "sim2real-pinned"
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


def _batch(ssm, selectors):
    """GetParameters: ({selector-as-asked: (Version, Value)}, sorted InvalidParameters)."""
    resp = ssm.get_parameters(Names=selectors)
    found = {}
    for p in resp["Parameters"]:
        asked = p.get("Selector")
        found[p["Name"] + (asked or "")] = (p["Version"], p["Value"])
    return found, sorted(resp.get("InvalidParameters", []))


def _delete_if_present(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response.get("Error", {}).get("Code") != "ParameterNotFound":
            raise


@tags("axis:rejection", "cap:c2", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteParameters removes a four-version parameter with a label on version 3 entirely:
    GetParameters puts every version and label selector under InvalidParameters, while a kept
    sibling in the same batch still resolves, and the dead name's history is refused.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_DeleteParameters.html
    """
    ssm = ctx.client("ssm")
    base = "/" + ctx.unique_name("sim2real-behav-batchdel-")
    doomed = f"{base}/doomed"
    kept = f"{base}/kept"
    ctx.on_cleanup(lambda: _delete_if_present(ssm, doomed))
    ctx.on_cleanup(lambda: _delete_if_present(ssm, kept))

    values = {v: f"rev-{v}-{'x' * v}" for v in range(1, 5)}
    for version, value in values.items():
        put = _call_with_retry(
            lambda v=value, n=version: ssm.put_parameter(Name=doomed, Value=v, Type="String", Overwrite=n > 1)
        )
        assert put["Version"] == version, f"PutParameter #{version} must mint Version {version}, got {put!r}"
    _call_with_retry(lambda: ssm.put_parameter(Name=kept, Value="survivor", Type="String"))
    labelled = _call_with_retry(lambda: ssm.label_parameter_version(Name=doomed, ParameterVersion=3, Labels=[_LABEL]))
    assert labelled.get("InvalidLabels", []) == [], f"label on version 3: {labelled!r}"

    selectors = [f"{doomed}:{v}" for v in values] + [f"{doomed}:{_LABEL}", doomed]
    want = {f"{doomed}:{v}": (v, values[v]) for v in values}
    want[f"{doomed}:{_LABEL}"] = (3, values[3])
    want[doomed] = (4, values[4])
    before = _poll(lambda: _batch(ssm, selectors + [kept]), lambda r: len(r[0]) == len(selectors) + 1,
                   what="every selector resolving through GetParameters")
    assert before == ({**want, kept: (1, "survivor")}, []), (
        f"before the delete GetParameters must resolve every selector exactly, got {before!r}"
    )

    deleted = ssm.delete_parameters(Names=[doomed])
    assert (deleted["DeletedParameters"], deleted["InvalidParameters"]) == ([doomed], []), (
        f"DeleteParameters must report exactly the one deleted name, got {deleted!r}"
    )

    after = _poll(lambda: _batch(ssm, selectors + [kept]), lambda r: len(r[0]) == 1,
                  what="the deleted parameter's selectors ceasing to resolve")
    assert after == ({kept: (1, "survivor")}, sorted(selectors)), (
        f"after the delete only {kept} may resolve and every selector of {doomed} must be "
        f"under InvalidParameters, got {after!r}"
    )
    gone = ("ParameterNotFound", "")
    history = _refusal(lambda: ssm.get_parameter_history(Name=doomed))
    assert history == gone, f"GetParameterHistory on the deleted parameter: expected {gone}, got {history!r}"
    again = ssm.delete_parameters(Names=[doomed, kept])
    assert (again["DeletedParameters"], again["InvalidParameters"]) == ([kept], [doomed]), (
        f"a second DeleteParameters must report the dead name invalid and delete the sibling, got {again!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
