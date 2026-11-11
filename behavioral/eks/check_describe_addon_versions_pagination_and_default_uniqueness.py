"""describe-addon-versions-pagination-and-default-uniqueness."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "describe-addon-versions-pagination-and-default-uniqueness"
GROUP = 'metadata'
SERVICES = ['eks']

# DescribeAddonVersionsRequestMaxResults is @range{min 1, max 100}. maxResults=1
# is the smallest legal page and therefore the strongest pagination probe.
_PAGE_LIMIT = 600


# Read-only against AWS-published reference data: nothing to create or clean up.


def _version_key(v):
    """Sort key for a Kubernetes version string like '1.31'."""
    parts = []
    for piece in str(v).split("."):
        digits = "".join(ch for ch in piece if ch.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def _pairs(addons):
    """Flatten a DescribeAddonVersions page into (addonName, addonVersion) pairs."""
    out = []
    for addon in addons:
        name = addon.get("addonName")
        for info in addon.get("addonVersions", []):
            out.append((name, info.get("addonVersion")))
    return out


def _counts(addons):
    """{addonName: number of addonVersions} -- the shape a truncating page size would shrink."""
    return {a.get("addonName"): len(a.get("addonVersions", [])) for a in addons}


def _walk(c, *, page_size=None, **filters):
    """Fully paginate DescribeAddonVersions; return (pages, flattened_pairs)."""
    pages = []
    token = None
    while True:
        kwargs = dict(filters)
        if page_size is not None:
            kwargs["maxResults"] = page_size
        if token:
            kwargs["nextToken"] = token
        resp = c.describe_addon_versions(**kwargs)
        pages.append(resp.get("addons", []))
        token = resp.get("nextToken")
        if not token:
            break
        assert len(pages) <= _PAGE_LIMIT, (
            f"DescribeAddonVersions pagination did not terminate within "
            f"{_PAGE_LIMIT} pages at maxResults={page_size!r}, filters={filters!r}"
        )
    flat = []
    for page in pages:
        flat.extend(_pairs(page))
    return pages, flat


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAddonVersions serves the full catalogue under any maxResults or nextToken with no
    nextToken returned, its owners/kubernetesVersion filters narrow it, and each (add-on, Kubernetes
    version) has at most one default version, exactly one for aws-owned add-ons.
    """
    c = ctx.client("eks")

    # Pinned to aws-owned add-ons at one Kubernetes version so the page count stays bounded.
    catalogue_pages, catalogue = _walk(c, owners=["aws"])
    assert catalogue, "the aws-owned add-on catalogue must not be empty"

    cluster_versions = set()
    for page in catalogue_pages:
        for addon in page:
            for info in addon.get("addonVersions", []):
                for compat in info.get("compatibilities", []):
                    if compat.get("clusterVersion"):
                        cluster_versions.add(compat["clusterVersion"])
    assert cluster_versions, (
        "no compatibilities[].clusterVersion anywhere in the aws-owned catalogue"
    )
    # Newest advertised version, derived from the catalogue itself rather than
    # hardcoded, so this check does not rot as Kubernetes versions retire.
    k8s = sorted(cluster_versions, key=_version_key)[-1]

    k8s_pages, single_call = _walk(c, owners=["aws"], kubernetesVersion=k8s)
    assert single_call, f"no aws-owned add-ons advertised for k8s {k8s}"

    # AWS does not paginate this operation: maxResults is inert, no nextToken is ever returned,
    # an out-of-range maxResults is accepted and a bogus nextToken is ignored. The contract is
    # completeness under an advisory page size; the filters are where a wrong answer shows.
    paged_pages, paged = _walk(
        c, page_size=1, owners=["aws"], kubernetesVersion=k8s
    )
    assert len(paged) == len(set(paged)), (
        f"maxResults=1 pagination returned a duplicate (addonName, addonVersion): "
        f"{sorted(p for p in set(paged) if paged.count(p) > 1)!r}"
    )
    assert set(paged) == set(single_call), (
        f"paginated walk disagrees with the single call for k8s {k8s}: "
        f"missing={sorted(set(single_call) - set(paged))!r} "
        f"extra={sorted(set(paged) - set(single_call))!r}"
    )
    for i, page in enumerate(paged_pages[:-1]):
        assert page, f"maxResults=1 produced empty non-terminal page {i}"

    # The smallest legal page size must not truncate: the same add-ons AND the same number of
    # versions per add-on come back, and no continuation token is offered.
    smallest = c.describe_addon_versions(
        owners=["aws"], kubernetesVersion=k8s, maxResults=1
    )
    unpaged = c.describe_addon_versions(owners=["aws"], kubernetesVersion=k8s)
    assert not smallest.get("nextToken"), (
        "DescribeAddonVersions must not offer a nextToken it cannot honour: real AWS serves the "
        f"whole catalogue at maxResults=1, got nextToken={smallest.get('nextToken')!r}"
    )
    assert not unpaged.get("nextToken"), unpaged.get("nextToken")
    assert _counts(smallest["addons"]) == _counts(unpaged["addons"]), (
        "maxResults=1 truncated the catalogue: real AWS returns the identical add-on -> version "
        f"count map with and without maxResults. maxResults=1 gave "
        f"{_counts(smallest['addons'])!r}, default page gave {_counts(unpaged['addons'])!r}"
    )
    # maxResults above the modelled max is ACCEPTED (no @range enforcement server-side) and
    # serves the same set -- an emulator that raises here diverges.
    over = c.describe_addon_versions(owners=["aws"], kubernetesVersion=k8s, maxResults=101)
    assert _counts(over["addons"]) == _counts(unpaged["addons"]), (
        f"maxResults=101 must be accepted and serve the same catalogue; got "
        f"{_counts(over['addons'])!r}"
    )
    # A nextToken this operation never issued is IGNORED, not rejected.
    bogus = c.describe_addon_versions(
        owners=["aws"], kubernetesVersion=k8s, nextToken="sim2real-behav-not-a-real-token"
    )
    assert _counts(bogus["addons"]) == _counts(unpaged["addons"]), (
        "real AWS ignores an unrecognised nextToken on DescribeAddonVersions and serves the "
        f"complete catalogue; got {_counts(bogus['addons'])!r}"
    )

    # The filters, by contrast, are NOT inert: they must actually narrow, and an unmatched
    # filter value yields an EMPTY list rather than an error or the unfiltered catalogue.
    unknown_version = c.describe_addon_versions(owners=["aws"], kubernetesVersion="9.99")
    assert unknown_version.get("addons") == [], (
        "kubernetesVersion the catalogue does not advertise must yield an empty addons list, "
        f"not an error and not the unfiltered catalogue; got "
        f"{len(unknown_version.get('addons', []))} add-ons"
    )
    unknown_owner = c.describe_addon_versions(owners=["sim2real-behav-no-such-owner"])
    assert unknown_owner.get("addons") == [], (
        f"an unmatched owners filter must yield an empty addons list; got "
        f"{len(unknown_owner.get('addons', []))} add-ons"
    )

    # No two versions of one add-on may both be the default for the same Kubernetes version.
    defaults: dict[tuple[str, str], set] = {}
    for page in catalogue_pages:
        for addon in page:
            name = addon.get("addonName")
            for info in addon.get("addonVersions", []):
                for compat in info.get("compatibilities", []):
                    if compat.get("defaultVersion"):
                        key = (name, compat.get("clusterVersion"))
                        defaults.setdefault(key, set()).add(info.get("addonVersion"))
    conflicts = {k: sorted(v) for k, v in defaults.items() if len(v) > 1}
    assert not conflicts, (
        f"more than one add-on version flagged defaultVersion for the same "
        f"(addonName, clusterVersion): {conflicts!r}; CreateAddon without an "
        f"explicit addonVersion would be non-deterministic"
    )

    # An aws-owned add-on at an advertised Kubernetes version has exactly one default, not zero.
    for addon in [a for page in k8s_pages for a in page]:
        name = addon.get("addonName")
        flagged = {
            info.get("addonVersion")
            for info in addon.get("addonVersions", [])
            for compat in info.get("compatibilities", [])
            if compat.get("clusterVersion") == k8s and compat.get("defaultVersion")
        }
        assert len(flagged) == 1, (
            f"aws-owned add-on {name!r} advertises {len(flagged)} default versions "
            f"for k8s {k8s} ({sorted(flagged)!r}); exactly one is required"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
