"""parameter-unlabel-partial-semantics."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "parameter-unlabel-partial-semantics"
GROUP = 'state-machine'
SERVICES = ['ssm']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UnlabelParameterVersion reports removed vs invalid labels and DescribeParameters filters."""

    ssm = ctx.client("ssm")

    def _param_name(suffix=""):
        # SSM requires a leading '/' for any hierarchical (slash-containing) name.
        return "/" + ctx.unique_name("sim2real-behav-" + suffix)

    def _track_parameter(name):
        ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
        return name

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

    name = _param_name("probe-param-unlabel-")
    _track_parameter(name)
    ssm.put_parameter(Name=name, Value="v1", Type="String")
    ssm.put_parameter(Name=name, Value="v2", Type="String", Overwrite=True)

    _call_with_retry(
        lambda: ssm.label_parameter_version(
            Name=name, ParameterVersion=1, Labels=["keep", "drop"]
        )
    )

    resp = _call_with_retry(
        lambda: ssm.unlabel_parameter_version(
            Name=name, ParameterVersion=1, Labels=["drop", "never-applied"]
        )
    )
    assert resp["RemovedLabels"] == ["drop"], (
        f"expected RemovedLabels ['drop'], got {resp['RemovedLabels']!r} (full: {resp})"
    )
    assert resp["InvalidLabels"] == ["never-applied"], (
        f"expected InvalidLabels ['never-applied'], got {resp['InvalidLabels']!r} (full: {resp})"
    )

    history = ssm.get_parameter_history(Name=name)["Parameters"]
    labels = next(p.get("Labels", []) for p in history if p["Version"] == 1)
    assert labels == ["keep"], (
        f"expected version 1's surviving label to be ['keep'] after the partial "
        f"unlabel, got {labels!r}"
    )

    described = ssm.describe_parameters(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [name]}]
    )["Parameters"]
    assert len(described) == 1, (
        f"expected exactly one parameter matching the Name filter, got {len(described)}: {described}"
    )
    assert described[0]["Type"] == "String", (
        f"expected Type 'String', got {described[0]['Type']!r}"
    )
    assert described[0]["Version"] == 2, (
        f"expected DescribeParameters to report the latest Version 2, got {described[0]['Version']!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
