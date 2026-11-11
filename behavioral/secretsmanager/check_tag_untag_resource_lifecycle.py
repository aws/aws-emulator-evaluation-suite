"""tag-untag-resource-lifecycle."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

CHECK = "tag-untag-resource-lifecycle"
GROUP = "state-machine"
SERVICES = ["secretsmanager"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource upserts tags visible via DescribeSecret; UntagResource removes them idempotently."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-sm-tags-")
    created = sm.create_secret(Name=name, SecretString="value")
    ctx.on_cleanup(lambda: _force_delete_secret(sm, created["ARN"]))

    sm.tag_resource(
        SecretId=name, Tags=[{"Key": "env", "Value": "test"}, {"Key": "team", "Value": "a"}]
    )
    desc = sm.describe_secret(SecretId=name)
    tags = {t["Key"]: t["Value"] for t in desc.get("Tags", [])}
    assert tags.get("env") == "test", f"expected env=test after TagResource, got {tags.get('env')!r}"
    assert tags.get("team") == "a", f"expected team=a after TagResource, got {tags.get('team')!r}"

    # upsert: re-tagging the same key overwrites the value
    sm.tag_resource(SecretId=name, Tags=[{"Key": "env", "Value": "prod"}])
    desc2 = sm.describe_secret(SecretId=name)
    tags2 = {t["Key"]: t["Value"] for t in desc2.get("Tags", [])}
    assert tags2.get("env") == "prod", f"expected TagResource upsert to overwrite env to prod, got {tags2.get('env')!r}"
    assert tags2.get("team") == "a", f"expected untouched key team=a to survive the upsert, got {tags2.get('team')!r}"

    sm.untag_resource(SecretId=name, TagKeys=["team"])
    desc3 = sm.describe_secret(SecretId=name)
    tags3 = {t["Key"]: t["Value"] for t in desc3.get("Tags", [])}
    assert "team" not in tags3, f"expected team removed by UntagResource, still present: {tags3!r}"
    assert tags3.get("env") == "prod", f"expected env=prod to survive UntagResource(team), got {tags3.get('env')!r}"

    # untagging a key that no longer exists must not error, and must not disturb the rest
    sm.untag_resource(SecretId=name, TagKeys=["team"])
    desc4 = sm.describe_secret(SecretId=name)
    tags4 = {t["Key"]: t["Value"] for t in desc4.get("Tags", [])}
    assert "team" not in tags4, f"expected team to remain absent after idempotent UntagResource, got {tags4!r}"
    assert tags4.get("env") == "prod", f"expected env=prod unchanged by idempotent UntagResource, got {tags4.get('env')!r}"


def _force_delete_secret(sm, secret_id: str) -> None:
    """Force-delete without a recovery window; an already-pending-deletion secret is
    restored first so the force delete can land."""
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except Exception:
        try:
            sm.restore_secret(SecretId=secret_id)
            sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
        except ClientError as exc:
            if exc.response["Error"]["Code"] != "ResourceNotFoundException":
                raise


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
