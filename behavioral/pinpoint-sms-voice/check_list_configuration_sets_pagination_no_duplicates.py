"""list-configuration-sets-pagination-no-duplicates."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "list-configuration-sets-pagination-no-duplicates"
GROUP = "state"
SERVICES = ["pinpoint-sms-voice"]

SET_COUNT = 6
SMALL_PAGE = "2"


def _list_all(client, page_size=None):
    names: list[str] = []
    pages: list[list[str]] = []
    token = None
    for _ in range(5000):
        kwargs = {}
        if page_size is not None:
            kwargs["PageSize"] = page_size
        if token:
            kwargs["NextToken"] = token
        resp = client.list_configuration_sets(**kwargs)
        page = resp.get("ConfigurationSets", [])
        pages.append(page)
        names.extend(page)
        token = resp.get("NextToken")
        if not token:
            return names, pages
    raise AssertionError("ListConfigurationSets pagination never terminated")


@tags("axis:happy-path", "cap:c2", "concern:representation", "plane:control")
def run(ctx) -> None:
    """Walking ListConfigurationSets with a small PageSize returns the names of one unpaged call with no
    duplicates and full non-final pages, including any set the check creates (a refused create gets
    AccessDeniedException "Access Denied")."""
    client = ctx.client("pinpoint-sms-voice")

    prefix = ctx.unique_name("sim2real-behav-cfgset-")
    created: list[str] = []
    for i in range(SET_COUNT):
        name = f"{prefix}{i}"
        try:
            client.create_configuration_set(ConfigurationSetName=name)
        except ClientError as e:
            code = e.response["Error"]["Code"]
            assert code == "AccessDeniedException", (
                f"expected AccessDeniedException on CreateConfigurationSet, got {code!r}"
            )
            message = e.response["Error"].get("Message")
            assert message == "Access Denied", f"expected the message 'Access Denied', got {message!r}"
            break
        else:
            created.append(name)

    if created:
        def _cleanup(names=tuple(created)):
            for n in names:
                client.delete_configuration_set(ConfigurationSetName=n)

        ctx.on_cleanup(_cleanup)

    unpaged, _ = _list_all(client)
    small, small_pages = _list_all(client, page_size=SMALL_PAGE)

    assert set(small) == set(unpaged), (
        f"paginated walk disagrees with an unpaged read; only in paginated walk="
        f"{sorted(set(small) - set(unpaged))}, only in unpaged read="
        f"{sorted(set(unpaged) - set(small))}"
    )
    assert len(small) == len(set(small)), (
        f"paginated walk repeated a configuration set: {len(small)} entries returned "
        f"but only {len(set(small))} distinct"
    )
    for name in created:
        assert name in unpaged, f"created set {name!r} is missing from ListConfigurationSets"

    if len(unpaged) >= 3:
        assert len(small_pages) >= 2, (
            f"{len(unpaged)} configuration sets at PageSize={SMALL_PAGE!r} should span "
            f"at least 2 pages, got {len(small_pages)}"
        )
        for page in small_pages[:-1]:
            assert len(page) == int(SMALL_PAGE), (
                f"non-final page returned {len(page)} of PageSize={SMALL_PAGE!r}, page sizes "
                f"were {[len(p) for p in small_pages]}"
            )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
