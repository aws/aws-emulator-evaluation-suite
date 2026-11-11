"""tags-added-and-removed-are-reflected-on-policy-and-system."""
from __future__ import annotations

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "tags-added-and-removed-are-reflected-on-policy-and-system"
GROUP = "tagging"
SERVICES = ["resiliencehubv2"]


def _teardown(undo, *not_found: str):
    """A cleanup running ``undo()``; only the resource's own not-found codes mean it is gone."""

    def run_undo() -> None:
        try:
            undo()
        except ClientError as exc:
            if exc.response["Error"]["Code"] in not_found:
                return
            raise

    return run_undo


def _create_policy(ctx, rh, **kwargs) -> dict:
    """A resilience policy deleted at teardown."""
    policy = rh.create_policy(name=ctx.unique_name("sim2real-behav-rhv2-pol-"), **kwargs)["policy"]
    arn = policy["policyArn"]
    ctx.on_cleanup(_teardown(lambda: rh.delete_policy(policyArn=arn), "ResourceNotFoundException"))
    return policy


def _create_system(ctx, rh, **kwargs) -> dict:
    """A system deleted at teardown."""
    system = rh.create_system(name=ctx.unique_name("sim2real-behav-rhv2-sys-"), **kwargs)["system"]
    arn = system["systemArn"]
    ctx.on_cleanup(_teardown(lambda: rh.delete_system(systemArn=arn), "ResourceNotFoundException"))
    return system


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource merges into creation tags, UntagResource removes only the named keys and ignores
    an absent one, and GetPolicy and GetSystem show the same tags as ListTagsForResource.
    """
    rh = ctx.client("resiliencehubv2")
    policy = _create_policy(ctx, rh, availabilitySlo={"target": 99.9}, tags={"team": "payments"})
    system = _create_system(ctx, rh, tags={"team": "payments"})
    for arn, read in ((policy["policyArn"], lambda: rh.get_policy(policyArn=policy["policyArn"])["policy"]),
                      (system["systemArn"], lambda: rh.get_system(systemArn=system["systemArn"])["system"])):
        assert rh.list_tags_for_resource(resourceArn=arn)["tags"] == {"team": "payments"}, "creation tags"
        rh.tag_resource(resourceArn=arn, tags={"stage": "prod", "team": "checkout"})
        merged = {"team": "checkout", "stage": "prod"}
        assert rh.list_tags_for_resource(resourceArn=arn)["tags"] == merged, "TagResource merges and overwrites"
        assert read()["tags"] == merged, f"the resource read must show the merged tags, got {read()['tags']!r}"
        rh.untag_resource(resourceArn=arn, tagKeys=["stage", "absent-key"])
        assert rh.list_tags_for_resource(resourceArn=arn)["tags"] == {"team": "checkout"}, "UntagResource"
        assert read()["tags"] == {"team": "checkout"}, f"after untag, got {read()['tags']!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
