"""get-parameters-by-path-pagination-token-exactness."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "get-parameters-by-path-pagination-token-exactness"
GROUP = 'state-machine'
SERVICES = ['ssm']


# GetParametersByPath is eventually consistent for a just-created parameter, so the
# first full read is polled to completeness.
def _error(fn):
    """Return the ClientError Error dict (Code and Message) raised by fn. An unexpected
    success raises, so a silently ignored input never reads as a code mismatch."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response.get("Error", {})
    raise AssertionError(f"the call was expected to be refused but it succeeded: {result!r}")


def _param_name(ctx, suffix=""):
    # SSM requires a leading '/' for any hierarchical (slash-containing) name.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix)


def _track_parameter(ctx, ssm, name):
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
    return name


def _poll(probe, predicate, timeout_s=90, interval_s=3.0):
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


def _drain(ssm, path, max_results, recursive=True):
    """Page GetParametersByPath to exhaustion. Returns (pages, names_in_order)."""
    pages = []
    names = []
    token = None
    for _ in range(25):  # bounded: 7 params at MaxResults=2 needs 4 pages
        kwargs = {"Path": path, "Recursive": recursive, "MaxResults": max_results}
        if token is not None:
            kwargs["NextToken"] = token
        resp = ssm.get_parameters_by_path(**kwargs)
        pages.append(resp)
        names.extend(p["Name"] for p in resp["Parameters"])
        token = resp.get("NextToken")
        if not token:
            return pages, names
    raise AssertionError(f"GetParametersByPath did not terminate for {path}")


@tags("axis:happy-path", "cap:c2", "concern:data-plane", "concern:negative-classes", "dp:api", "plane:data")
def run(ctx) -> None:
    """Paging GetParametersByPath with NextToken returns every parameter exactly once, ends
    with a tokenless page, replays a token to the same page and refuses a corrupted token;
    Recursive=False excludes deeper parameters."""

    ssm = ctx.client("ssm")

    base = _param_name(ctx, "page-")
    expected = set()
    for i in range(7):
        name = f"{base}/leaf{i:02d}"
        _track_parameter(ctx, ssm, name)
        ssm.put_parameter(
            Name=name,
            Value=f"page-value-{i:02d}",
            Type="String",
            Tags=[{"Key": "sim2real-check", "Value": CHECK}],
        )
        expected.add(name)

    # One parameter a level deeper, to give the Recursive=False control something
    # it must exclude.
    sibling = f"{base}/sub/leafdeep"
    _track_parameter(ctx, ssm, sibling)
    ssm.put_parameter(
        Name=sibling,
        Value="deep",
        Type="String",
        Tags=[{"Key": "sim2real-check", "Value": CHECK}],
    )
    expected_recursive = expected | {sibling}

    # Wait for all 8 to be readable at all before making exactness claims.
    _poll(
        lambda: set(_drain(ssm, base, 10)[1]),
        lambda got: got == expected_recursive,
    )

    # --- paged drain at MaxResults=2 ---------------------------------------
    pages, names = _drain(ssm, base, 2)
    assert len(names) == len(set(names)), (
        f"a paged drain must not repeat a parameter; got {sorted(names)}"
    )
    assert set(names) == expected_recursive, (
        "the union of all pages must equal the collection exactly; missing "
        f"{sorted(expected_recursive - set(names))}, extra {sorted(set(names) - expected_recursive)}"
    )
    # No exact page count: a page may hold "between zero and MaxResults" items (Smithy).
    for i, page in enumerate(pages[:-1]):
        assert page.get("NextToken"), (
            f"page {i} is not the last page and must carry a NextToken, got {page.keys()}"
        )
    assert not pages[-1].get("NextToken"), (
        f"the final page must not carry a NextToken, got {pages[-1].get('NextToken')!r}"
    )
    tokens = [p["NextToken"] for p in pages[:-1]]
    assert len(set(tokens)) == len(tokens), (
        f"each page must mint a distinct NextToken, got {tokens}"
    )

    # --- token replay: the same token must resolve to the same page ---------
    replay = ssm.get_parameters_by_path(
        Path=base, Recursive=True, MaxResults=2, NextToken=tokens[0]
    )
    assert [p["Name"] for p in replay["Parameters"]] == [
        p["Name"] for p in pages[1]["Parameters"]
    ], (
        "re-using a NextToken must return the same page it originally produced: "
        f"{[p['Name'] for p in replay['Parameters']]} != "
        f"{[p['Name'] for p in pages[1]['Parameters']]}"
    )

    # --- corrupted token must be refused, not ignored -----------------------
    bad = _error(
        lambda: ssm.get_parameters_by_path(
            Path=base,
            Recursive=True,
            MaxResults=2,
            NextToken="sim2real-behav-not-a-real-token",
        )
    )
    assert bad.get("Code") == "InvalidNextToken", (
        f"a malformed NextToken must be refused with InvalidNextToken, got {bad!r}"
    )
    expected_message = "The following token is invalid: sim2real-behav-not-a-real-token."
    assert bad.get("Message") == expected_message, (
        f"expected message {expected_message!r}, got {bad.get('Message')!r}"
    )

    # --- Recursive=False control: the same paging path, one fewer member ----
    _, shallow = _drain(ssm, base, 2, recursive=False)
    assert set(shallow) == expected, (
        "Recursive=False must return exactly the immediate children and must exclude "
        f"{sibling}; got {sorted(shallow)}"
    )
    assert sibling not in shallow, (
        f"{sibling} is two levels below {base} and must not appear with Recursive=False"
    )
    assert len(shallow) == len(set(shallow)) == 7, (
        f"expected exactly 7 immediate children, got {sorted(shallow)}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
