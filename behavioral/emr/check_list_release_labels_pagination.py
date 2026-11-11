"""list-release-labels-pagination."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-release-labels-pagination"
GROUP = 'release-labels'
SERVICES = ['emr']

def _error_code(fn):
    """Call fn(); return botocore Error.Code, raising if the call unexpectedly succeeds."""
    try:
        fn()
    except ClientError as exc:
        return exc.response.get("Error", {}).get("Code")
    raise AssertionError("expected ListReleaseLabels to reject the call, but it succeeded")

@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """MaxResults/NextToken paginate ListReleaseLabels without repeating or losing labels, a
    full drain sees no duplicates and is stable across two immediate listings, and a
    tampered NextToken is rejected outright rather than silently restarting."""
    emr = ctx.client("emr")
    first = emr.list_release_labels(MaxResults=1)
    assert len(first["ReleaseLabels"]) == 1, (
        f"MaxResults=1 must return exactly one label, got {first['ReleaseLabels']}"
    )
    token = first.get("NextToken")
    assert token, "a truncated ListReleaseLabels page must carry a NextToken"

    second = emr.list_release_labels(MaxResults=1, NextToken=token)
    assert len(second["ReleaseLabels"]) == 1, (
        f"MaxResults=1 with NextToken must still return exactly one label, got {second['ReleaseLabels']}"
    )
    assert second["ReleaseLabels"][0] != first["ReleaseLabels"][0], (
        "the second page must not repeat the first page's label"
    )

    def collect_all():
        labels: list = []
        tok = None
        while True:
            resp = emr.list_release_labels(NextToken=tok) if tok else emr.list_release_labels()
            labels.extend(resp["ReleaseLabels"])
            tok = resp.get("NextToken")
            if not tok:
                break
        return labels

    pass1 = collect_all()
    assert len(pass1) == len(set(pass1)), "ListReleaseLabels returned a duplicate label across pages"
    assert first["ReleaseLabels"][0] in pass1, (
        "the label seen on the first MaxResults=1 page is missing from the full listing"
    )

    pass2 = collect_all()
    assert set(pass1) == set(pass2), (
        "ListReleaseLabels membership changed across two immediate full listings"
    )

    code = _error_code(lambda: emr.list_release_labels(NextToken="sim2real-behav-bogus-token"))
    assert code, "ListReleaseLabels must reject a tampered NextToken with a specific error code"

if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
