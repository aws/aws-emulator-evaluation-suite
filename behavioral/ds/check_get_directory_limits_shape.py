"""get-directory-limits-shape."""

from __future__ import annotations

from behavioral_harness import tags


CHECK = "get-directory-limits-shape"
GROUP = 'lifecycle'
SERVICES = ['ds']

_CATEGORIES = ("CloudOnlyDirectories", "CloudOnlyMicrosoftAD", "ConnectedDirectories")


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """GetDirectoryLimits reports integer Limit and CurrentCount and a boolean LimitReached for cloud-only
    Simple AD, cloud-only Microsoft AD and connected directories, with CurrentCount <= Limit and
    LimitReached true exactly when CurrentCount reached Limit."""
    ds = ctx.client("ds")
    limits = ds.get_directory_limits()["DirectoryLimits"]

    for category in _CATEGORIES:
        limit_key = f"{category}Limit"
        count_key = f"{category}CurrentCount"
        reached_key = f"{category}LimitReached"

        limit = limits.get(limit_key)
        count = limits.get(count_key)
        reached = limits.get(reached_key)

        assert isinstance(limit, int), f"{limit_key}: expected int, got {limit!r} in {limits}"
        assert isinstance(count, int), f"{count_key}: expected int, got {count!r} in {limits}"
        assert isinstance(reached, bool), f"{reached_key}: expected bool, got {reached!r} in {limits}"

        assert count <= limit, (
            f"{count_key} ({count}) exceeds {limit_key} ({limit}) -- current usage must never "
            f"exceed the reported ceiling"
        )
        assert reached == (count >= limit), (
            f"{reached_key} is {reached} but {count_key}={count} and {limit_key}={limit} "
            f"implies it should be {count >= limit}"
        )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
