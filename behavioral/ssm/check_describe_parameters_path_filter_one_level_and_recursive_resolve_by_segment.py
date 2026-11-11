"""describe-parameters-path-filter-one-level-and-recursive-resolve-by-segment."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "describe-parameters-path-filter-one-level-and-recursive-resolve-by-segment"
GROUP = 'state-machine'
SERVICES = ['ssm']


def _delete_if_present(ssm, name):
    try:
        ssm.delete_parameter(Name=name)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ParameterNotFound":
            raise


def _described(ssm, path, option):
    return {
        p["Name"]: (p["Type"], p["Version"])
        for page in ssm.get_paginator("describe_parameters").paginate(
            ParameterFilters=[{"Key": "Path", "Option": option, "Values": [path]}]
        )
        for p in page.get("Parameters", [])
    }


def _settled(probe, want, timeout_s=30.0):
    """probe() once it equals want, or its last answer at the deadline, which the caller then grades."""
    deadline = time.monotonic() + timeout_s
    while True:
        got = probe()
        if got == want or time.monotonic() >= deadline:
            return got
        time.sleep(2.0)


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "dp:api", "plane:data")
def run(ctx) -> None:
    """DescribeParameters with a Path filter resolves by hierarchy segment: OneLevel lists only the
    direct children and Recursive every descendant, with their types and versions, and neither
    lists a sibling that only shares the path as a string prefix.

    Reference: https://docs.aws.amazon.com/systems-manager/latest/APIReference/API_ParameterStringFilter.html
    """
    ssm = ctx.client("ssm")
    base = "/" + ctx.unique_name("sim2real-behav-descpath-")
    created = {
        f"{base}/top": ("String", 2),
        f"{base}/list": ("StringList", 1),
        f"{base}/deep/leaf": ("String", 1),
        f"{base}/deep/deeper/leaf": ("String", 3),
        f"{base}-decoy/leaf": ("String", 1),
        f"{base}x": ("String", 1),
    }
    for name, (kind, versions) in created.items():
        for n in range(1, versions + 1):
            ssm.put_parameter(Name=name, Value=f"v{n}", Type=kind, Overwrite=n > 1)
            if n == 1:
                ctx.on_cleanup(lambda nm=name: _delete_if_present(ssm, nm))

    want_one = {f"{base}/top": ("String", 2), f"{base}/list": ("StringList", 1)}
    one = _settled(lambda: _described(ssm, base, "OneLevel"), want_one)
    assert one == want_one, (
        f"Path OneLevel {base}: expected exactly {want_one!r}, got {one!r}"
    )
    want = {n: tv for n, tv in created.items() if n.startswith(base + "/")}
    rec = _settled(lambda: _described(ssm, base, "Recursive"), want)
    assert rec == want, f"Path Recursive {base}: expected exactly {want!r}, got {rec!r}"
    deep = _described(ssm, f"{base}/deep", "OneLevel")
    assert deep == {f"{base}/deep/leaf": ("String", 1)}, f"Path OneLevel {base}/deep: got {deep!r}"

    ssm.delete_parameter(Name=f"{base}/deep/leaf")
    want_after = {n: tv for n, tv in want.items() if n != f"{base}/deep/leaf"}
    rec_after = _settled(lambda: _described(ssm, base, "Recursive"), want_after)
    assert rec_after == want_after, (
        f"Path Recursive {base} after deleting {base}/deep/leaf: expected {want_after!r}, got {rec_after!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
