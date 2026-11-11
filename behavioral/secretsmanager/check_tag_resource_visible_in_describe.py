"""tag-resource-visible-in-describe."""
from __future__ import annotations

from behavioral_harness import tags
from botocore.exceptions import ClientError

def _force_delete(sm, secret_id):
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _create_secret(sm, ctx, name=None, secret_string="initial-value", **kwargs):
    """Create a secret, register its force-delete teardown, and return the raw response."""
    if name is None:
        name = ctx.unique_name("sim2real-behav-" + "secret-")
    params = {"Name": name}
    if secret_string is not None:
        params["SecretString"] = secret_string
    params.update(kwargs)
    resp = sm.create_secret(**params)
    ctx.on_cleanup(lambda: _force_delete(sm, name))
    return resp

CHECK = "tag-resource-visible-in-describe"
GROUP = 'state-machine'
SERVICES = ['secretsmanager']

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """TagResource attaches tags that are then visible via DescribeSecret."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(sm, ctx, name=name)

    sm.tag_resource(SecretId=name, Tags=[{"Key": "env", "Value": "test"}])

    desc = sm.describe_secret(SecretId=name)
    tags = {t["Key"]: t["Value"] for t in desc.get("Tags", [])}
    assert tags.get("env") == "test", f"expected tag env=test after TagResource, got Tags={desc.get('Tags')}"

    sm.untag_resource(SecretId=name, TagKeys=["env"])
    desc2 = sm.describe_secret(SecretId=name)
    tags2 = {t["Key"]: t["Value"] for t in desc2.get("Tags", [])}
    assert "env" not in tags2, f"expected tag env removed after UntagResource, got Tags={desc2.get('Tags')}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
