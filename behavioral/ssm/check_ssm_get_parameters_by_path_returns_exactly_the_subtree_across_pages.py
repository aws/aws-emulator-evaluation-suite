"""ssm-get-parameters-by-path-returns-exactly-the-subtree-across-pages."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "ssm-get-parameters-by-path-returns-exactly-the-subtree-across-pages"
GROUP = 'parameter-store'
SERVICES = ['ssm']

_THROTTLE = ("TooManyUpdates", "ThrottlingException", "ParameterLimitExceeded")


def _param_name(ctx, suffix=""):
    # SSM requires a leading '/' for any hierarchical (slash-containing) name.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix)


def _error(fn):
    """Call fn(); return its botocore error (code, message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}")


# Teardown deletes retry too: ctx.on_cleanup swallows exceptions, so a throttled delete would leak.
def _call_with_retry(fn, retries=12, delay=2.0):
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


def _poll(probe, predicate, timeout_s=120, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _delete_all(ssm, names):
    """Batch-delete every parameter the check created, ten at a time, retrying throttles."""
    remaining = list(names)
    for i in range(0, len(remaining), 10):
        chunk = remaining[i : i + 10]
        _call_with_retry(lambda c=chunk: ssm.delete_parameters(Names=c))


def _drain(ssm, path, max_results, recursive):
    """Page GetParametersByPath to exhaustion. Returns (n_pages, {name: value})."""
    values = {}
    pages = 0
    token = None
    for _ in range(60):  # bounded: 25 parameters at MaxResults=10 needs 3 pages
        kwargs = {"Path": path, "Recursive": recursive, "MaxResults": max_results}
        if token is not None:
            kwargs["NextToken"] = token
        resp = _call_with_retry(lambda k=dict(kwargs): ssm.get_parameters_by_path(**k))
        pages += 1
        for p in resp["Parameters"]:
            assert p["Name"] not in values, (
                f"{p['Name']!r} was served twice while paging {path!r}"
            )
            values[p["Name"]] = p["Value"]
        token = resp.get("NextToken")
        if not token:
            return pages, values
    raise AssertionError(f"GetParametersByPath did not terminate for {path!r}")


@tags("axis:happy-path", "concern:representation", "dp:api", "plane:data", "cap:c1")
def run(ctx) -> None:
    """GetParametersByPath matches by hierarchy segment, not prefix: a recursive drain returns
    exactly the 25-member subtree without prefix-sharing decoys, Recursive=False only level one,
    GetParameters agrees on values, and deleting one member shrinks the subtree by exactly one.
    """

    ssm = ctx.client("ssm")

    base = _param_name(ctx, "tree-")

    created: list[str] = []
    # One cleanup over the live list, so a failure part-way through creation tears down what exists.
    cleanup_registered = False

    def _put(name, value):
        nonlocal cleanup_registered
        _call_with_retry(
            lambda: ssm.put_parameter(
                Name=name,
                Value=value,
                Type="String",
                Tags=[{"Key": "sim2real-check", "Value": CHECK}],
            )
        )
        created.append(name)
        if not cleanup_registered:
            ctx.on_cleanup(lambda: _delete_all(ssm, created))
            cleanup_registered = True

    # The subtree: 8 + 9 + 8 = 25 members at three nesting levels.
    immediate = {}
    for i in range(8):
        name = f"{base}/a{i:02d}"
        immediate[name] = f"level1-{i:02d}"
        _put(name, immediate[name])

    level2 = {}
    for i in range(9):
        name = f"{base}/mid/b{i:02d}"
        level2[name] = f"level2-{i:02d}"
        _put(name, level2[name])

    level3 = {}
    for i in range(8):
        name = f"{base}/mid/deep/c{i:02d}"
        level3[name] = f"level3-{i:02d}"
        _put(name, level3[name])

    expected = {**immediate, **level2, **level3}
    assert len(expected) == 25, f"the subtree must hold 25 distinct names, got {len(expected)}"

    # Every decoy satisfies startswith(base) but is not a descendant of it.
    decoys = {
        f"{base}-other/d00": "decoy-sibling-0",
        f"{base}-other/d01": "decoy-sibling-1",
        f"{base}x/d02": "decoy-extended-prefix",
    }
    for name, value in decoys.items():
        _put(name, value)
        assert name.startswith(base), (
            f"the decoy {name!r} must be a string prefix-match of {base!r} or it proves nothing"
        )
        assert not name.startswith(base + "/"), (
            f"the decoy {name!r} must NOT be a hierarchy descendant of {base!r}"
        )

    _poll(
        lambda: set(_drain(ssm, base, 10, True)[1]),
        lambda got: got == set(expected),
    )

    pages, recursive = _drain(ssm, base, 10, True)
    recursive_names = set(recursive)
    assert recursive_names == set(expected), (
        "the recursive read must return exactly the subtree; missing "
        f"{sorted(set(expected) - recursive_names)!r}, unexpected "
        f"{sorted(recursive_names - set(expected))!r}"
    )
    # A page holds "between zero and MaxResults" items (Smithy), so 25 at MaxResults=10 take at
    # least 3 pages, not exactly 3.
    assert pages == 3 or pages > 3, (
        f"25 parameters at MaxResults=10 must take at least 3 pages, took {pages} — fewer "
        "means a page exceeded MaxResults"
    )
    leaked = recursive_names & set(decoys)
    assert not leaked, (
        "GetParametersByPath resolved the path as a string prefix rather than a hierarchy "
        f"segment: {sorted(leaked)!r} are siblings of {base!r}, not descendants"
    )
    assert recursive == expected, (
        "every member's value must survive the listing; mismatches at "
        f"{sorted(k for k in expected if recursive.get(k) != expected[k])!r}"
    )

    shallow_pages, shallow = _drain(ssm, base, 10, False)
    assert set(shallow) == set(immediate), (
        f"Recursive=False must return exactly the 8 immediate children of {base!r}; got "
        f"{sorted(shallow)!r}"
    )
    assert shallow == immediate, (
        "the non-recursive values must match too; mismatches at "
        f"{sorted(k for k in immediate if shallow.get(k) != immediate[k])!r}"
    )

    # Control: the decoys are reachable, so their absence above is scoping, not a failed create.
    _, other = _drain(ssm, f"{base}-other", 10, True)
    assert other == {k: v for k, v in decoys.items() if k.startswith(base + "-other")}, (
        f"the decoy sibling path must return its own two members, got {sorted(other)!r}"
    )

    batch_names = sorted(expected)[:10]
    batch = _call_with_retry(lambda: ssm.get_parameters(Names=batch_names))
    assert batch.get("InvalidParameters", []) == [], (
        f"GetParameters reported invalid names: {batch.get('InvalidParameters')!r}"
    )
    batch_values = {p["Name"]: p["Value"] for p in batch["Parameters"]}
    assert batch_values == {k: expected[k] for k in batch_names}, (
        "GetParameters and GetParametersByPath must agree on every value; got "
        f"{batch_values!r}"
    )

    removed = sorted(expected)[0]
    ssm.delete_parameter(Name=removed)
    created.remove(removed)
    removed_code, removed_message = _error(lambda: ssm.get_parameter(Name=removed))
    assert removed_code == "ParameterNotFound", (
        f"a deleted parameter must be gone from GetParameter, got {removed_code!r} for {removed!r}"
    )
    assert removed_message == "", removed_message
    _, after_delete = _drain(ssm, base, 10, True)
    assert set(after_delete) == set(expected) - {removed}, (
        "deleting one member must shrink the subtree by exactly one, no more no less; "
        f"missing {sorted((set(expected) - {removed}) - set(after_delete))!r}, unexpected "
        f"{sorted(set(after_delete) - (set(expected) - {removed}))!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
