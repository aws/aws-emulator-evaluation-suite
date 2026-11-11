"""jd-describe-pagination-covers-all-revisions."""

from __future__ import annotations

from behavioral_harness import tags


CHECK = "jd-describe-pagination-covers-all-revisions"
GROUP = 'job-definition'
SERVICES = ['batch']


def _swallow(fn):
    """Run a teardown step; any failure raises."""
    fn()


def _deregister_jd(bat, name, revision):
    _swallow(lambda: bat.deregister_job_definition(jobDefinition=f"{name}:{revision}"))


_MANAGED_TAGS = {"sim2real:managed": "true", "sim2real:prefix": "sim2real-behav-jd-page-"}


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeJobDefinitions honours maxResults and nextToken across revisions."""
    bat = ctx.client("batch")
    name = ctx.unique_name("sim2real-behav-jd-page-")
    registered: list[int] = []
    for i in range(3):
        resp = bat.register_job_definition(
            jobDefinitionName=name,
            type="container",
            containerProperties={"image": "busybox:1.36", "vcpus": 1, "memory": 128, "command": ["echo", str(i)]},
            tags=_MANAGED_TAGS,
        )
        rev = resp["revision"]
        registered.append(rev)
        ctx.on_cleanup(lambda r=rev: _deregister_jd(bat, name, r))

    seen: list[int] = []
    token = None
    pages = 0
    while True:
        kwargs = {"jobDefinitionName": name, "maxResults": 1}
        if token:
            kwargs["nextToken"] = token
        page = bat.describe_job_definitions(**kwargs)
        got = page["jobDefinitions"]
        assert len(got) <= 1, f"maxResults=1 must return at most one item, got {len(got)}"
        seen.extend(d["revision"] for d in got)
        token = page.get("nextToken")
        pages += 1
        if not token or pages > 10:
            break

    assert sorted(seen) == sorted(registered), (
        f"pagination must yield every registered revision exactly once, "
        f"registered {sorted(registered)}, got {seen}"
    )
    assert pages >= 3, f"expected at least 3 pages with maxResults=1, got {pages}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
