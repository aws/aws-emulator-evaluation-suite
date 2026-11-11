"""query-vectors-metadata-filter-operator-table."""

# Each of the 14 filters below must select exactly the key set this file RECOMPUTES in pure
# Python from the same metadata documents, for an index of 6 vectors queried with topK == 6 --
# both the SOUNDNESS half (every returned key satisfies the filter) and the COMPLETENESS half
# (a filtered query over a 6-vector index returns no fewer keys than expected). Operator
# semantics are taken verbatim from the operator table in
# "Metadata filtering" (Amazon S3 User Guide, s3-vectors-metadata-filtering.html): $eq, $ne, $gt,
# $gte, $lt, $lte, $in, $nin, $exists, $and, $or, a bare value meaning $eq, and "when comparing
# with an array metadata value, $eq returns true if the input value matches any element in the
# array". Number metadata written as a Python int/float is compared numerically, not lexically.
#
# Ambiguous cases are DELIBERATELY EXCLUDED rather than guessed, because a guessed rule is worse
# than no rule. Excluded: $ne / $nin / any comparison operator against a vector that LACKS the field
# (the docs do not say whether an absent field is "not equal" or simply unmatched), and
# $exists:false. Every $ne and $nin case here is on `year`, which every vector carries.

from __future__ import annotations

import time
from typing import Any

from behavioral_harness import tags

CHECK = "query-vectors-metadata-filter-operator-table"
GROUP = "vector"
SERVICES = ["s3vectors"]

_DIMENSION = 4
_QUERY = [1.0, 0.0, 0.0, 0.0]

# Six vectors whose metadata is arranged so every operator below selects a NON-EMPTY PROPER
# subset (asserted as a construction guard). `featured` is absent from one vector on purpose,
# and it is used only with $exists; `genre` is present on every vector so the $eq/$in/$and/$or
# cases below never touch the undocumented "operator against an absent field" case. `tags` is a
# list on one vector, for the documented array-$eq rule.
_VECTORS: dict[str, dict[str, Any]] = {
    "m1": {"year": 2018, "rating": 6.5, "genre": "drama", "tags": ["plain"], "featured": True},
    "m2": {"year": 2019, "rating": 7.0, "genre": "comedy", "tags": ["plain"], "featured": True},
    "m3": {"year": 2020, "rating": 8.5, "genre": "drama", "tags": ["plain"], "featured": True},
    "m4": {
        "year": 2021,
        "rating": 9.0,
        "genre": "documentary",
        "tags": ["plain"],
        "featured": True,
    },
    "m5": {"year": 2022, "rating": 5.5, "genre": "thriller", "tags": ["plain"]},
    "m6": {
        "year": 2023,
        "rating": 7.5,
        "genre": "comedy",
        "tags": ["award", "cult"],
        "featured": True,
    },
}

# The ONE field deliberately absent from one vector. Every operator other than $exists is used
# only on fields every vector carries, so no assertion in this file ever depends on the
# undocumented "operator against an absent field" case.
_OPTIONAL_FIELD = "featured"

_FILTERS: dict[str, Any] = {
    "bare-value-implies-eq": {"genre": "drama"},
    "explicit-eq": {"genre": {"$eq": "comedy"}},
    "ne-on-present-field": {"year": {"$ne": 2020}},
    "gt": {"year": {"$gt": 2020}},
    "gte": {"year": {"$gte": 2020}},
    "lt": {"rating": {"$lt": 7.0}},
    "lte": {"rating": {"$lte": 7.0}},
    "in": {"genre": {"$in": ["comedy", "documentary"]}},
    "nin-on-present-field": {"year": {"$nin": [2018, 2019]}},
    "exists-true": {"featured": {"$exists": True}},
    "and": {"$and": [{"genre": {"$eq": "comedy"}}, {"year": {"$gte": 2020}}]},
    "or": {"$or": [{"genre": {"$eq": "documentary"}}, {"rating": {"$lt": 6.0}}]},
    "range-on-one-field": {"year": {"$gte": 2019, "$lte": 2021}},
    "array-value-eq-matches-element": {"tags": {"$eq": "cult"}},
}


@tags(
    "axis:happy-path",
    "cap:c2",
    "concern:data-plane",
    "concern:representation",
    "dp:api",
    "plane:data",
)
def run(ctx) -> None:
    """Every documented QueryVectors metadata-filter operator selects exactly the set a pure-
    Python evaluation of the same filter over the same metadata predicts -- soundness (nothing
    returned that fails the filter) asserted unconditionally, completeness asserted per case."""
    s3v = ctx.client("s3vectors")
    account = ctx.client("sts").get_caller_identity()["Account"]
    assert account, "STS returned no account id; the check cannot attribute its resources"

    all_keys = set(_VECTORS)

    # Two construction guards on the LOCAL table, before a single call is made.
    #  (1) No case may reference an ABSENT field with anything but $exists -- that case's semantics
    #      are undocumented, and a guessed rule is worse than none.
    #  (2) No case may match everything or nothing: such a case cannot distinguish a working
    #      filter from an ignored one and would be decoration.
    expected = {}
    for name, filt in _FILTERS.items():
        for field, op in _referenced_fields(filt):
            if op == "$exists":
                continue
            missing = [k for k, meta in _VECTORS.items() if field not in meta]
            assert not missing, (
                f"filter case {name!r} applies {op} to field {field!r}, which vectors {missing} "
                "do not carry; operator-vs-absent-field semantics are undocumented and excluded"
            )
        matched = {k for k, meta in _VECTORS.items() if _matches(filt, meta)}
        assert matched and matched != all_keys, (
            f"filter case {name!r} selects {sorted(matched)} out of {sorted(all_keys)}; a case "
            "that matches everything or nothing cannot discriminate and must be re-designed"
        )
        expected[name] = matched
    assert any(_OPTIONAL_FIELD not in meta for meta in _VECTORS.values()), (
        f"the $exists case is only meaningful if some vector lacks {_OPTIONAL_FIELD!r}"
    )

    bucket = ctx.unique_name("sim2real-s3v-filt-")
    s3v.create_vector_bucket(
        vectorBucketName=bucket,
        tags={"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav"},
    )
    ctx.on_cleanup(lambda: s3v.delete_vector_bucket(vectorBucketName=bucket))

    index = ctx.unique_name("sim2real-s3v-filt-idx-")
    s3v.create_index(
        vectorBucketName=bucket,
        indexName=index,
        dataType="float32",
        dimension=_DIMENSION,
        distanceMetric="euclidean",
    )
    ctx.on_cleanup(lambda: s3v.delete_index(vectorBucketName=bucket, indexName=index))

    # Spread the vectors along one axis so no two are equidistant from the query -- distance
    # plays no part in the assertions, but a deterministic geometry keeps a failure legible.
    s3v.put_vectors(
        vectorBucketName=bucket,
        indexName=index,
        vectors=[
            {
                "key": key,
                "data": {"float32": [1.0, float(i) / 10.0, 0.0, 0.0]},
                "metadata": dict(meta),
            }
            for i, (key, meta) in enumerate(sorted(_VECTORS.items()))
        ],
    )
    ctx.on_cleanup(
        lambda: s3v.delete_vectors(vectorBucketName=bucket, indexName=index, keys=sorted(all_keys))
    )

    def _query(filt: Any | None) -> list[dict]:
        kwargs: dict[str, Any] = {
            "vectorBucketName": bucket,
            "indexName": index,
            # topK equals the population, so truncation can never be confused with filtering.
            "topK": len(all_keys),
            "queryVector": {"float32": list(_QUERY)},
            "returnMetadata": True,
        }
        if filt is not None:
            kwargs["filter"] = filt
        return s3v.query_vectors(**kwargs)["vectors"]

    # Bounded retry, reason: newly written vectors are not instantly queryable. The UNFILTERED
    # query is the baseline: it must see all six before any filter result means anything.
    baseline = _poll_until(
        lambda: _query(None),
        lambda vs: len(vs) == len(all_keys),
        timeout_s=60.0,
        interval_s=2.0,
        description=f"all {len(all_keys)} vectors became queryable",
    )
    assert {v["key"] for v in baseline} == all_keys, (
        f"unfiltered baseline returned {sorted(v['key'] for v in baseline)}, expected "
        f"{sorted(all_keys)}"
    )

    for name in sorted(_FILTERS):
        filt = _FILTERS[name]
        returned = _query(filt)
        got = {v["key"] for v in returned}

        # SOUNDNESS -- holds no matter what the ANN candidate set does. Every returned vector's
        # OWN metadata, as the service reports it, must satisfy the filter when evaluated
        # locally. This is the leg that catches a target that ignores `filter` outright.
        for item in returned:
            meta = item["metadata"]
            assert _matches(filt, meta), (
                f"filter case {name!r} ({filt!r}) returned key {item['key']!r} whose metadata "
                f"{meta!r} does not satisfy the filter"
            )

        # COMPLETENESS -- the hypothesis-bearing half.
        assert got == expected[name], (
            f"filter case {name!r} ({filt!r}) returned {sorted(got)}, expected "
            f"{sorted(expected[name])}; missing {sorted(expected[name] - got)}, extra "
            f"{sorted(got - expected[name])}"
        )


# A pure-Python evaluator for the documented filter grammar. It RAISES on any construct whose
# semantics the docs leave open, so this file can never silently assert a guess.
_COMPARISONS = ("$eq", "$ne", "$gt", "$gte", "$lt", "$lte", "$in", "$nin", "$exists")


def _matches(filt: Any, meta: dict) -> bool:
    assert isinstance(filt, dict), f"a filter must be a document, got {filt!r}"
    for key, condition in filt.items():
        if key == "$and":
            assert condition, "$and takes a non-empty array of filters"
            if not all(_matches(sub, meta) for sub in condition):
                return False
        elif key == "$or":
            assert condition, "$or takes a non-empty array of filters"
            if not any(_matches(sub, meta) for sub in condition):
                return False
        elif key.startswith("$"):
            raise AssertionError(f"unsupported top-level filter operator {key!r}")
        elif isinstance(condition, dict):
            for op, operand in condition.items():
                assert op in _COMPARISONS, f"unsupported field operator {op!r} on {key!r}"
                if not _compare(op, key, operand, meta):
                    return False
        else:
            # "When you don't specify an operator, S3 Vectors automatically uses the $eq
            # operator." -- Metadata filtering, S3 User Guide.
            if not _compare("$eq", key, condition, meta):
                return False
    return True


def _referenced_fields(filt: Any) -> list[tuple[str, str]]:
    """Every (field, operator) pair a filter document reaches, so the construction guard can
    refuse a case whose semantics the docs leave open."""
    out: list[tuple[str, str]] = []
    for key, condition in filt.items():
        if key in ("$and", "$or"):
            for sub in condition:
                out.extend(_referenced_fields(sub))
        elif isinstance(condition, dict):
            out.extend((key, op) for op in condition)
        else:
            out.append((key, "$eq"))
    return out


def _compare(op: str, field: str, operand: Any, meta: dict) -> bool:
    present = field in meta
    if op == "$exists":
        assert operand is True, (
            "$exists:false is excluded from this table: the docs do not state whether it also "
            "matches a vector whose field is present-but-null, so asserting it would be a guess"
        )
        return present
    if not present:
        # Unreachable for _FILTERS: the construction guard in run() refuses any non-$exists case
        # over a field some vector lacks. Reached only when evaluating SERVICE-returned metadata
        # for the SOUNDNESS leg, where "no field, no match" is the conservative reading and keeps
        # the failure message the one the reader wants ("returned a key that fails the filter").
        return False
    value = meta[field]
    if op in ("$eq", "$ne"):
        # Documented array rule: $eq is true if the operand matches ANY element.
        if isinstance(value, list):
            assert op == "$eq", (
                f"$ne against an array metadata value ({field!r}={value!r}) is undocumented and "
                "excluded from this table"
            )
            return operand in value
        return (value == operand) if op == "$eq" else (value != operand)
    assert not isinstance(value, list), (
        f"operator {op!r} against an array metadata value ({field!r}={value!r}) is undocumented "
        "and excluded from this table"
    )
    if op in ("$in", "$nin"):
        assert operand, f"{op} takes a non-empty array of primitives"
        return (value in operand) if op == "$in" else (value not in operand)
    assert isinstance(value, (int, float)) and not isinstance(value, bool), (
        f"operator {op!r} is documented for Number only; {field!r} holds {value!r}"
    )
    if op == "$gt":
        return value > operand
    if op == "$gte":
        return value >= operand
    if op == "$lt":
        return value < operand
    return value <= operand


def _poll_until(probe, predicate, *, timeout_s: float, interval_s: float, description: str) -> Any:
    """Bounded retry that RAISES on deadline miss -- never returns its last value."""
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"{description} not reached within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
