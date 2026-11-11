"""untag-user."""
from __future__ import annotations

from behavioral_harness import tags


CHECK = "untag-user"
GROUP = 'tags'
SERVICES = ['iam']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """UntagUser removes a specific tag key from a user."""
    iam = ctx.client("iam")
    user = ctx.unique_name("sim2real-behav-user-")
    iam.create_user(UserName=user, Path="/")
    ctx.on_cleanup(lambda n=user: iam.delete_user(UserName=n))
    iam.tag_user(
        UserName=user,
        Tags=[
            {"Key": "keep", "Value": "yes"},
            {"Key": "remove", "Value": "no"},
        ],
    )
    iam.untag_user(UserName=user, TagKeys=["remove"])
    resp = iam.list_user_tags(UserName=user)
    tag_keys = [t["Key"] for t in resp["Tags"]]
    assert "keep" in tag_keys, f"expected 'keep' to survive untag, got tag keys {tag_keys}"
    assert "remove" not in tag_keys, f"expected 'remove' to be gone after untag, got tag keys {tag_keys}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
