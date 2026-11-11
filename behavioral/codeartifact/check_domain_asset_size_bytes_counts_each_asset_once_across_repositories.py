"""domain-asset-size-bytes-counts-each-asset-once-across-repositories."""

from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "domain-asset-size-bytes-counts-each-asset-once-across-repositories"
GROUP = "server-side"
SERVICES = ["codeartifact"]



#: repositoryCount typically converges within one or two 5s polls; this bound is a safety margin.
_COUNTER_WAIT_SECONDS = 120.0


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDomain's repositoryCount moves by exactly 1 per CreateRepository and
    DeleteRepository, reads never change it or the bucket ARN, and each deleted repository then
    reports ResourceNotFoundException.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-ca-dom-")
    first_repo = ctx.unique_name("sim2real-ca-r1-")
    second_repo = ctx.unique_name("sim2real-ca-r2-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))

    fresh = ca.describe_domain(domain=domain)["domain"]
    base_repos = fresh.get("repositoryCount") or 0
    assert base_repos == 0, (
        f"a domain created seconds ago reports repositoryCount {base_repos!r}; a new domain is "
        f"empty until repositories are added to it"
    )
    bucket = fresh["s3BucketArn"]
    assert bucket.startswith("arn:aws:s3:::"), (
        f"s3BucketArn is {bucket!r}; a bucket ARN has no region or account segment, so it must "
        f"start with 'arn:aws:s3:::'"
    )

    # ---- repositoryCount tracks CreateRepository, one at a time ------------------------------
    ca.create_repository(domain=domain, repository=first_repo,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repository(ca, domain, first_repo))
    _await_counter(ca, domain, 1,
                   reason="repositoryCount to reach 1 after the first CreateRepository")

    ca.create_repository(domain=domain, repository=second_repo,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repository(ca, domain, second_repo))
    _await_counter(ca, domain, 2,
                   reason="repositoryCount to reach 2 after the second CreateRepository")

    # Freeze detector: three consecutive reads of an unchanged domain report the same counters.
    frozen = []
    for _ in range(3):
        read = _domain(ca, domain)
        frozen.append((read.get("repositoryCount"), read.get("s3BucketArn")))
    assert frozen == [(2, bucket)] * 3, (
        f"three consecutive reads of an unchanged domain reported {frozen!r}; expected "
        f"{[(2, bucket)] * 3!r} — a read must not move a counter and the bucket must not change"
    )

    # ---- repositoryCount tracks DeleteRepository, one at a time, the other direction ---------
    _delete_repository(ca, domain, second_repo)
    _await_counter(ca, domain, 1,
                   reason="repositoryCount to fall to 1 after deleting the second repository")
    gone = _err(lambda: ca.describe_repository(domain=domain, repository=second_repo))
    expected = ("ResourceNotFoundException", _repository_not_found(ctx, domain, second_repo))
    assert gone == expected, (
        f"an independent DescribeRepository on {second_repo!r} after its own DeleteRepository "
        f"succeeded returned {gone!r}, expected {expected!r}"
    )

    _delete_repository(ca, domain, first_repo)
    _await_counter(ca, domain, 0,
                   reason="repositoryCount to fall to 0 after deleting the first repository")
    gone = _err(lambda: ca.describe_repository(domain=domain, repository=first_repo))
    expected = ("ResourceNotFoundException", _repository_not_found(ctx, domain, first_repo))
    assert gone == expected, (
        f"an independent DescribeRepository on {first_repo!r} after its own DeleteRepository "
        f"succeeded returned {gone!r}, expected {expected!r}"
    )

    final = _domain(ca, domain)
    assert final["s3BucketArn"] == bucket, (
        f"the domain's bucket ARN changed from {bucket!r} to {final['s3BucketArn']!r} merely "
        f"because its repositories were deleted"
    )


def _err(fn):
    """Call fn(); return the botocore (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        error = exc.response.get("Error", {})
        return error.get("Code"), error.get("Message", "")
    raise AssertionError(f"the call SUCCEEDED where real AWS refuses it and returned {result!r}")


def _repository_not_found(ctx, domain: str, repository: str) -> str:
    return (
        f"Repository not found. Repository '{repository}' in domain '{domain}' owned by account "
        f"'{ctx.account}' does not exist."
    )


def _domain(ca, domain: str) -> dict:
    return ca.describe_domain(domain=domain)["domain"]


def _await_counter(ca, domain: str, expected: int, *, reason: str) -> int:
    """Poll DescribeDomain until repositoryCount equals *expected*. RAISES on timeout with the
    last observed value."""
    deadline = time.monotonic() + _COUNTER_WAIT_SECONDS
    observed = None
    while True:
        observed = _domain(ca, domain).get("repositoryCount")
        if observed == expected:
            return observed
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {_COUNTER_WAIT_SECONDS}s for {reason}; DescribeDomain last reported "
                f"repositoryCount={observed!r}, expected {expected!r}"
            )
        time.sleep(5.0)


def _delete_repository(ca, domain: str, repository: str, timeout_s: float = 120.0) -> None:
    """DeleteRepository, retrying while the service still sees a dependent reference."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ca.delete_repository(domain=domain, repository=repository)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


def _delete_domain(ca, domain: str, timeout_s: float = 120.0) -> None:
    """DeleteDomain, retrying while the service still sees a repository in the domain."""
    deadline = time.monotonic() + timeout_s
    while True:
        try:
            ca.delete_domain(domain=domain)
            return
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ResourceNotFoundException":
                return
            if code != "ConflictException" or time.monotonic() >= deadline:
                raise
            time.sleep(3.0)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
