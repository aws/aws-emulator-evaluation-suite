"""list-users-by-path-prefix."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "list-users-by-path-prefix"
GROUP = 'path_handling'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """ListUsers with PathPrefix filters to users under that path."""
    iam = ctx.client("iam")
    path = "/sim2real/userpath/"
    name1 = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=name1, Path=path)
    ctx.on_cleanup(lambda n=name1: iam.delete_user(UserName=n))
    name2 = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=name2, Path="/")
    ctx.on_cleanup(lambda n=name2: iam.delete_user(UserName=n))
    resp = iam.list_users(PathPrefix=path)
    matches = {u["UserName"]: u for u in resp["Users"]}
    assert name1 in matches, f"expected {name1!r} under {path!r}, got {sorted(matches)}"
    assert matches[name1]["Path"] == path, f"expected Path {path!r}, got {matches[name1]['Path']!r}"
    assert name2 not in matches, f"PathPrefix={path!r} leaked {name2!r} (Path=/), got {sorted(matches)}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
