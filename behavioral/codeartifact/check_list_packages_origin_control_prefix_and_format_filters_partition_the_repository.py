"""list-packages-origin-control-prefix-and-format-filters-partition-the-repository."""

from __future__ import annotations

import hashlib
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-packages-origin-control-prefix-and-format-filters-partition-the-repository"
GROUP = "ordering"
SERVICES = ["codeartifact"]

_NAMESPACE = "sim2real"
_PAYLOAD = b"sim2real list-packages filter fixture\n"

#: How long a changed origin restriction may take to show up in the ListPackages filter index.
_FILTER_WAIT_SECONDS = 180.0


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListPackages' publish/upstream, packagePrefix, namespace and format filters each partition
    the repository at the service, compose as AND, and apply on every page.
    """
    ca = ctx.client("codeartifact")
    domain = ctx.unique_name("sim2real-ca-dom-")
    repository = ctx.unique_name("sim2real-ca-repo-")

    ca.create_domain(domain=domain, tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_domain(ca, domain))
    ca.create_repository(domain=domain, repository=repository,
                         tags=[{"key": "sim2real", "value": CHECK}])
    ctx.on_cleanup(lambda: _delete_repository(ca, domain, repository))

    # Three generic packages under one prefix plus one under a different prefix, so the prefix filter
    # has something to exclude and the origin filter has something to partition.
    suffix = ctx.unique_name("")
    kept = [f"alpha-{n}-{suffix}" for n in ("one", "two", "three")]
    other = f"beta-one-{suffix}"
    for package in [*kept, other]:
        ca.publish_package_version(
            domain=domain, repository=repository, format="generic", namespace=_NAMESPACE,
            package=package, packageVersion="1.0.0", assetContent=_PAYLOAD,
            assetName="payload.bin", assetSHA256=hashlib.sha256(_PAYLOAD).hexdigest())
        ctx.on_cleanup(lambda p=package: _delete_package(ca, domain, repository, p))

    everything = _packages(ca, domain, repository)
    assert everything == {*kept, other}, (
        f"the unfiltered listing is {sorted(everything)!r}, expected exactly the four packages this "
        f"check published {sorted([*kept, other])!r}"
    )

    # A directly-published generic package defaults to publish=ALLOW, upstream=BLOCK.
    for package in [*kept, other]:
        restrictions = ca.describe_package(
            domain=domain, repository=repository, format="generic", namespace=_NAMESPACE,
            package=package)["package"]["originConfiguration"]["restrictions"]
        assert restrictions == {"publish": "ALLOW", "upstream": "BLOCK"}, (
            f"{package!r} reports origin restrictions {restrictions!r}; a directly-published package "
            f"defaults to {{'publish': 'ALLOW', 'upstream': 'BLOCK'}}, and the filters below "
            f"partition against that baseline"
        )

    # Every package matches ALLOW and none matches BLOCK, before anything is changed.
    base_allow = _packages(ca, domain, repository, publish="ALLOW")
    assert base_allow == everything, (
        f"ListPackages(publish='ALLOW') returned {sorted(base_allow)!r}, expected all four "
        f"{sorted(everything)!r}"
    )
    base_block = _packages(ca, domain, repository, publish="BLOCK")
    assert base_block == set(), (
        f"ListPackages(publish='BLOCK') returned {sorted(base_block)!r} before any package was set "
        f"to BLOCK; expected nothing"
    )

    target = kept[1]
    ca.put_package_origin_configuration(
        domain=domain, repository=repository, format="generic", namespace=_NAMESPACE,
        package=target, restrictions={"publish": "BLOCK", "upstream": "BLOCK"})
    blocked = _poll(
        lambda: _packages(ca, domain, repository, publish="BLOCK"),
        lambda s: s == {target}, timeout_s=_FILTER_WAIT_SECONDS, interval_s=5.0,
        reason=f"ListPackages(publish='BLOCK') to return exactly {target!r} after its restriction "
               f"was flipped")
    assert blocked == {target}, (
        f"ListPackages(publish='BLOCK') returned {sorted(blocked)!r}; exactly one of four packages "
        f"was set to BLOCK, so exactly {target!r} must come back"
    )
    allowed = _packages(ca, domain, repository, publish="ALLOW")
    assert allowed == {kept[0], kept[2], other}, (
        f"ListPackages(publish='ALLOW') returned {sorted(allowed)!r}, expected the three still-ALLOW "
        f"packages {sorted([kept[0], kept[2], other])!r}"
    )
    assert allowed.isdisjoint(blocked) and allowed | blocked == everything, (
        f"the two publish filters returned {sorted(allowed)!r} and {sorted(blocked)!r}, which do not "
        f"partition the unfiltered {sorted(everything)!r}"
    )
    # The `upstream` dimension is independent: all four are upstream=BLOCK, so that filter must
    # return all four even though only one is publish=BLOCK.
    upstream_blocked = _packages(ca, domain, repository, upstream="BLOCK")
    assert upstream_blocked == everything, (
        f"ListPackages(upstream='BLOCK') returned {sorted(upstream_blocked)!r}, expected all four "
        f"{sorted(everything)!r} — publish and upstream are separate restrictions and the filters "
        f"must not be aliases of one another"
    )
    upstream_allowed = _packages(ca, domain, repository, upstream="ALLOW")
    assert upstream_allowed == set(), (
        f"ListPackages(upstream='ALLOW') returned {sorted(upstream_allowed)!r}, expected nothing"
    )

    prefixed = _packages(ca, domain, repository, packagePrefix="alpha-")
    assert prefixed == set(kept), (
        f"ListPackages(packagePrefix='alpha-') returned {sorted(prefixed)!r}, expected the three "
        f"alpha packages {sorted(kept)!r} and not {other!r}"
    )
    exact = _packages(ca, domain, repository, packagePrefix=target)
    assert exact == {target}, (
        f"a packagePrefix naming one package in full returned {sorted(exact)!r}, expected exactly "
        f"[{target!r}]"
    )
    unmatched = _packages(ca, domain, repository, packagePrefix="gamma-")
    assert unmatched == set(), (
        f"a packagePrefix matching nothing returned {sorted(unmatched)!r}, expected nothing"
    )
    combined = _packages(ca, domain, repository, packagePrefix="alpha-", publish="ALLOW")
    assert combined == {kept[0], kept[2]}, (
        f"ListPackages(packagePrefix='alpha-', publish='ALLOW') returned {sorted(combined)!r}; the "
        f"two filters must compose as AND, giving the alpha packages that are still ALLOW "
        f"{sorted([kept[0], kept[2]])!r} — an OR would return {sorted(set(kept) | allowed)!r}"
    )

    # namespace has prefix-matching semantics despite its name; it is rejected without format.
    format_missing = _error(
        lambda: ca.list_packages(domain=domain, repository=repository, namespace=_NAMESPACE))
    expected_format_missing = (
        "ValidationException", "PackageFormat cannot be null when PackageNamespace is not null")
    assert format_missing == expected_format_missing, (
        f"ListPackages(namespace={_NAMESPACE!r}) with no format returned {format_missing!r}, "
        f"expected {expected_format_missing!r} — namespace alone is not a well-formed filter"
    )
    ns_exact = _packages(ca, domain, repository, format="generic", namespace=_NAMESPACE)
    assert ns_exact == everything, (
        f"ListPackages(format='generic', namespace={_NAMESPACE!r}) returned {sorted(ns_exact)!r}, "
        f"expected all four — every package here is in that namespace"
    )
    ns_prefix = _packages(ca, domain, repository, format="generic", namespace=_NAMESPACE[:4])
    assert ns_prefix == everything, (
        f"ListPackages(format='generic', namespace={_NAMESPACE[:4]!r}) returned "
        f"{sorted(ns_prefix)!r}; the model states this argument has prefix-matching semantics "
        f"despite its name, so a strict-equality implementation returns nothing here"
    )
    ns_miss = _packages(ca, domain, repository, format="generic", namespace="zzz-not-a-namespace")
    assert ns_miss == set(), (
        f"ListPackages with a namespace prefix matching nothing returned {sorted(ns_miss)!r}, "
        f"expected nothing"
    )

    generic = _packages(ca, domain, repository, format="generic")
    assert generic == everything, (
        f"ListPackages(format='generic') returned {sorted(generic)!r}, expected all four "
        f"{sorted(everything)!r}"
    )
    npm_shaped = _packages(ca, domain, repository, format="npm")
    assert npm_shaped == set(), (
        f"ListPackages(format='npm') returned {sorted(npm_shaped)!r}; nothing npm-shaped was "
        f"published into this repository"
    )

    ca.put_package_origin_configuration(
        domain=domain, repository=repository, format="generic", namespace=_NAMESPACE,
        package=target, restrictions={"publish": "ALLOW", "upstream": "BLOCK"})
    restored = _poll(
        lambda: _packages(ca, domain, repository, publish="ALLOW"),
        lambda s: s == everything, timeout_s=_FILTER_WAIT_SECONDS, interval_s=5.0,
        reason="ListPackages(publish='ALLOW') to return all four again after the restriction was "
               "restored")
    assert restored == everything, (
        f"ListPackages(publish='ALLOW') returned {sorted(restored)!r} after {target!r} was restored "
        f"to ALLOW, expected all four {sorted(everything)!r}"
    )
    # Terminal read: an independent operation confirms the restored value, so the filter above is
    # agreeing with the stored state rather than both being stale.
    final = ca.describe_package(
        domain=domain, repository=repository, format="generic", namespace=_NAMESPACE,
        package=target)["package"]["originConfiguration"]["restrictions"]
    assert final == {"publish": "ALLOW", "upstream": "BLOCK"}, (
        f"DescribePackage reports {final!r} for {target!r} after the restore, expected "
        f"{{'publish': 'ALLOW', 'upstream': 'BLOCK'}}"
    )
    empty_block = _packages(ca, domain, repository, publish="BLOCK")
    assert empty_block == set(), (
        f"ListPackages(publish='BLOCK') returned {sorted(empty_block)!r} after the restore, "
        f"expected nothing"
    )


def _packages(ca, domain: str, repository: str, **filters) -> set[str]:
    """Every page of ListPackages under *filters*, one package per page.

    maxResults=1 forces the filter to apply on every page, not only the first.
    """
    out, next_token = set(), None
    while True:
        page = ca.list_packages(domain=domain, repository=repository, maxResults=1, **filters,
                                **({"nextToken": next_token} if next_token else {}))
        out.update(p["package"] for p in page["packages"])
        next_token = page.get("nextToken")
        if not next_token:
            return out


def _error(fn):
    """Call fn() and return its (error code, message); raise if the call unexpectedly succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        return exc.response["Error"]["Code"], exc.response["Error"].get("Message", "")
    raise AssertionError(
        f"real AWS rejects this call, but it SUCCEEDED and returned {result!r}"
    )


def _poll(read, predicate, *, timeout_s: float, interval_s: float, reason: str):
    """Bounded retry on an observable condition. RAISES on timeout, naming what it waited for."""
    deadline = time.monotonic() + timeout_s
    while True:
        observed = read()
        if predicate(observed):
            return observed
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"waited {timeout_s}s for {reason}; last observation was {observed!r}"
            )
        time.sleep(interval_s)


def _delete_package(ca, domain: str, repository: str, package: str) -> None:
    try:
        ca.delete_package(domain=domain, repository=repository, format="generic",
                          namespace=_NAMESPACE, package=package)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise


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
