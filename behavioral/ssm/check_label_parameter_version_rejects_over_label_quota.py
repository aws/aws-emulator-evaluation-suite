"""label-parameter-version-rejects-over-label-quota."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "label-parameter-version-rejects-over-label-quota"
GROUP = 'overly-permissive'
SERVICES = ['ssm']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """Overly-permissive check: a parameter version accepts at most 10 labels; the 11th is rejected.

    Real SSM caps a single parameter version at 10 labels. An emulator that
    accepts an 11th label is overly permissive.
    """

    ssm = ctx.client("ssm")

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    def _track_parameter(name):
        ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
        return name

    def _error(fn):
        """Call fn(); return its botocore Error dict (Code and Message). An unexpected SUCCESS raises, because
        an emulator ACCEPTING an 11th label real AWS refuses is the strongest signal available."""
        try:
            result = fn()
        except ClientError as exc:
            return exc.response.get("Error", {})
        raise AssertionError(
            f"real AWS rejects an 11th label on a version already at the 10-label cap, "
            f"but the call SUCCEEDED and returned {result!r}"
        )

    def _call_with_retry(fn, retries=10, delay=3.0):
        last = None
        for _ in range(retries):
            try:
                return fn()
            except ClientError as exc:
                last = exc
                code = exc.response.get("Error", {}).get("Code")
                if code in ("TooManyUpdates", "ThrottlingException"):
                    time.sleep(delay)
                    continue
                raise
        raise last

    name = _param_name("probe-param-labels-")
    _track_parameter(name)
    ssm.put_parameter(Name=name, Value="v1", Type="String")

    ten = [f"lbl-{i}" for i in range(10)]
    resp = _call_with_retry(
        lambda: ssm.label_parameter_version(
            Name=name, ParameterVersion=1, Labels=ten
        )
    )
    assert not resp.get("InvalidLabels"), (
        f"positive control: expected no InvalidLabels labeling version 1 with exactly 10 "
        f"labels, got {resp.get('InvalidLabels')!r}"
    )

    err = _error(
        lambda: ssm.label_parameter_version(
            Name=name, ParameterVersion=1, Labels=["lbl-overflow"]
        )
    )
    assert err.get("Code") == "ParameterVersionLabelLimitExceeded", (
        f"expected error code 'ParameterVersionLabelLimitExceeded' adding an 11th label to a "
        f"version already at the 10-label cap, got {err!r}"
    )
    expected_message = (
        "A parameter version can have maximum 10 labels.Move one or more labels to another "
        "version and try again."
    )
    assert err.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {err.get('Message')!r}"
    )

    history = ssm.get_parameter_history(Name=name)["Parameters"]
    labels = next(p.get("Labels", []) for p in history if p["Version"] == 1)
    assert sorted(labels) == sorted(ten), (
        f"the rejected 11th label must not have taken effect: expected version 1's labels to "
        f"still be exactly {sorted(ten)!r}, got {sorted(labels)!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
