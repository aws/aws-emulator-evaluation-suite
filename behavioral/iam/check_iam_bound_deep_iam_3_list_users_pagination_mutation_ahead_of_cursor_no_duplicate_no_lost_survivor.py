"""iam-bound-deep-iam-3-list-users-pagination-mutation-ahead-of-cursor-no-duplicate-no-lost-survivor."""
from __future__ import annotations

import time

from behavioral_harness import tags

CHECK = "iam-bound-deep-iam-3-list-users-pagination-mutation-ahead-of-cursor-no-duplicate-no-lost-survivor"
GROUP = "pagination"
SERVICES = ["iam"]

_SEED_USERS = 24
_PAGE = 5


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListUsers Marker pagination with a delete and a create AHEAD of the cursor mid-walk: no
    duplicate UserId, the deleted user is not returned, and every surviving user appears once.
    """
    iam = ctx.client("iam")
    base = ctx.unique_name("sim2real-pgm-")
    path = f"/{base}/"

    created: dict[str, str] = {}  # UserName -> UserId
    for i in range(_SEED_USERS):
        name = f"{base}-{i:02d}"
        user = iam.create_user(UserName=name, Path=path)["User"]
        ctx.on_cleanup(lambda n=name: _quiet(lambda: iam.delete_user(UserName=n)))
        created[name] = user["UserId"]

    # IAM listings are eventually consistent: wait until a full walk sees every seed user.
    seen = _walk_until(ctx, iam, path, lambda ids: set(created.values()) <= ids)
    missing = sorted(n for n, uid in created.items() if uid not in seen)
    assert not missing, f"seed users never became visible under {path!r}: {missing!r}"

    pages: list[list[dict]] = []
    first = iam.list_users(PathPrefix=path, MaxItems=_PAGE)
    pages.append(first["Users"])
    assert first.get("IsTruncated") is True, f"page 1 of {_SEED_USERS} users not truncated: {first.get('IsTruncated')!r}"
    marker = first.get("Marker")
    assert marker, f"truncated page 1 carried no Marker: keys {sorted(first)!r}"
    page1_ids = {u["UserId"] for u in first["Users"]}
    assert page1_ids, "page 1 returned no users"

    # IAM's Marker is positional: mutating BEHIND the cursor skips or repeats users, so mutate ahead.
    unreturned = sorted(n for n, uid in created.items() if uid not in page1_ids)
    victim_name = unreturned[len(unreturned) // 2]
    victim_id = created[victim_name]
    iam.delete_user(UserName=victim_name)
    late_name = f"{base}-zz-late"
    late = iam.create_user(UserName=late_name, Path=path)["User"]
    ctx.on_cleanup(lambda: _quiet(lambda: iam.delete_user(UserName=late_name)))
    created[late_name] = late["UserId"]
    _walk_until(ctx, iam, path, lambda ids: late["UserId"] in ids and victim_id not in ids)

    # Resume the original walk on page 1's Marker.
    for _ in range(50):
        resp = iam.list_users(PathPrefix=path, MaxItems=_PAGE, Marker=marker)
        pages.append(resp["Users"])
        if not resp.get("IsTruncated"):
            break
        marker = resp.get("Marker")
        assert marker, f"page {len(pages)} truncated without a Marker"
    else:
        raise AssertionError("pagination did not terminate within 50 pages")

    where: dict[str, list[int]] = {}
    for idx, page in enumerate(pages, start=1):
        assert len(page) <= _PAGE, f"page {idx} returned {len(page)!r} users, above MaxItems={_PAGE}"
        for u in page:
            assert u["Path"] == path, f"user {u['UserName']!r} with Path {u['Path']!r} leaked into the {path!r} walk"
            where.setdefault(u["UserId"], []).append(idx)

    dupes = {uid: p for uid, p in where.items() if len(p) > 1}
    assert not dupes, f"UserIds returned on more than one page: {dupes!r}"
    assert victim_id not in where, f"deleted user {victim_name!r} was still returned on pages {where.get(victim_id)!r}"

    survivors = {name: uid for name, uid in created.items() if uid != victim_id}
    lost = sorted(name for name, uid in survivors.items() if uid not in where)
    assert not lost, f"surviving users never returned by the mutated walk: {lost!r}"


def _full_walk(iam, path: str) -> list[dict]:
    users: list[dict] = []
    for page in iam.get_paginator("list_users").paginate(PathPrefix=path):
        users.extend(page["Users"])
    return users


def _walk_until(ctx, iam, path: str, done, total_s: float = 60.0) -> set[str]:
    """Full-walk UserIds every 1 s until done(ids) holds or total_s (capped by the run) passes."""
    left = ctx.time_left()
    deadline = time.monotonic() + (total_s if left is None else min(total_s, max(left - 5.0, 0.0)))
    while True:
        ids = {u["UserId"] for u in _full_walk(iam, path)}
        if done(ids) or time.monotonic() >= deadline:
            return ids
        time.sleep(1)


def _quiet(fn) -> None:
    from botocore.exceptions import ClientError
    try:
        fn()
    except ClientError as e:
        if e.response["Error"]["Code"] != "NoSuchEntity":
            raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
