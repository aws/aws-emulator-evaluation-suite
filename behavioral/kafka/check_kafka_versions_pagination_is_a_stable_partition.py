"""kafka-versions-pagination-is-a-stable-partition."""
from __future__ import annotations

from behavioral_harness import tags

CHECK = "kafka-versions-pagination-is-a-stable-partition"
GROUP = 'kafka-versions'
SERVICES = ['kafka']

# KafkaVersionStatus is a closed enum in the Smithy model. A version outside it is not a
# "new value we do not know about" -- it is a value no SDK can deserialise into the enum.
_STATUS_VOCABULARY = {"ACTIVE", "DEPRECATED"}
_MAX_PAGES = 200


def _drain(fn, list_key, **kwargs):
    """Drain a paginated op, returning (flat_items, pages) where pages is a list of lists."""
    items, pages, token = [], [], None
    for _ in range(_MAX_PAGES):
        page_kwargs = dict(kwargs)
        if token:
            page_kwargs["NextToken"] = token
        resp = fn(**page_kwargs)
        page = resp.get(list_key, [])
        pages.append(page)
        items.extend(page)
        token = resp.get("NextToken")
        if not token:
            return items, pages
    raise AssertionError(f"{list_key} pagination did not terminate within {_MAX_PAGES} pages")


def _rows(items):
    """The catalog row identity: real MSK keys a version row by (Version, Status).

    ListKafkaVersions can list the same version string twice, once ACTIVE and once
    DEPRECATED. A version STRING is therefore not a row identity; the pair is.
    """
    return [(v["Version"], v.get("Status")) for v in items]


@tags("axis:happy-path", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListKafkaVersions paged at several MaxResults sizes drains to the same set of (Version, Status) rows
    as the unique unpaged call, never fewer rows and no page over MaxResults, with every Status ACTIVE or
    DEPRECATED."""
    msk = ctx.client("kafka")

    bulk = msk.list_kafka_versions()
    bulk_rows = _rows(bulk.get("KafkaVersions", []))
    assert bulk_rows, "ListKafkaVersions returned no versions"
    assert "NextToken" not in bulk, (
        "the unpaginated ListKafkaVersions truncated the catalog; this check compares it "
        f"against the drained result, so a NextToken here invalidates the comparison: "
        f"{bulk.get('NextToken')!r}"
    )
    assert len(set(bulk_rows)) == len(bulk_rows), (
        f"the unpaginated ListKafkaVersions repeated a (Version, Status) row, so the repetition "
        f"is not a cursor artefact but a duplicated catalog entry: {sorted(bulk_rows)}"
    )

    # Three page sizes: 1 forces the maximum number of boundaries, 5 and 10 are boundaries that
    # do not divide the 37-row catalog evenly. All three must cover the same set.
    for page_size in (1, 5, 10):
        paged_items, pages = _drain(
            msk.list_kafka_versions, "KafkaVersions", MaxResults=page_size
        )
        paged_rows = _rows(paged_items)
        assert set(paged_rows) == set(bulk_rows), (
            f"MaxResults={page_size} changed the catalog: "
            f"only-when-paged={sorted(set(paged_rows) - set(bulk_rows))}, "
            f"only-when-unpaged={sorted(set(bulk_rows) - set(paged_rows))}"
        )
        assert len(paged_rows) >= len(bulk_rows), (
            f"MaxResults={page_size} drained {len(paged_rows)} rows but the unpaginated call "
            f"returns {len(bulk_rows)}; a cursor may repeat a row, it may never lose one"
        )
        oversized = [(i, len(p)) for i, p in enumerate(pages) if len(p) > page_size]
        assert not oversized, (
            f"MaxResults={page_size} was ignored on page(s) {oversized} of the drain"
        )
        assert len(pages) >= 2, (
            f"MaxResults={page_size} returned the whole {len(bulk_rows)}-row catalog in "
            f"{len(pages)} page(s); MaxResults was not honoured at all"
        )

        bad_status = sorted(
            {r for r in paged_rows if r[1] not in _STATUS_VOCABULARY}
        )
        assert not bad_status, (
            f"KafkaVersionStatus is the closed enum {sorted(_STATUS_VOCABULARY)}; these entries "
            f"carry a value outside it: {bad_status}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
