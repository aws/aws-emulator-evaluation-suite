"""tag-resource-reserved-prefix-fails."""
from __future__ import annotations

import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

def _error_code(fn):
    """Call fn(); return (Error.Code, Error.Message). An unexpected SUCCESS raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected this call to be refused, but it SUCCEEDED and returned {result!r}")

def _force_delete(sm, secret_id):
    try:
        sm.delete_secret(SecretId=secret_id, ForceDeleteWithoutRecovery=True)
    except ClientError as exc:
        if exc.response["Error"]["Code"] != "ResourceNotFoundException":
            raise

def _poll_for_tag(sm, secret_id, key, expected_value, timeout_s=30.0):
    deadline = time.monotonic() + timeout_s
    last_tags = {}
    while time.monotonic() < deadline:
        desc = sm.describe_secret(SecretId=secret_id)
        last_tags = {t["Key"]: t["Value"] for t in desc.get("Tags", [])}
        if last_tags.get(key) == expected_value:
            return last_tags
        time.sleep(2)
    return last_tags

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

CHECK = "tag-resource-reserved-prefix-fails"
GROUP = 'overly-permissive'
SERVICES = ['secretsmanager']

@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """TagResource must reject tag keys starting with the reserved 'aws:' prefix."""
    sm = ctx.client("secretsmanager")
    name = ctx.unique_name("sim2real-behav-secret-")
    _create_secret(sm, ctx, name=name)

    code, message = _error_code(
        lambda: sm.tag_resource(SecretId=name, Tags=[{"Key": "aws:reserved", "Value": "x"}])
    )
    assert code == "InvalidParameterException", f"expected InvalidParameterException, got {code}"
    assert message == "You can't modify system tags. Tag key: 'aws:reserved'.", (
        f"unexpected reserved-prefix message: {message!r}"
    )

    desc = sm.describe_secret(SecretId=name)
    tags = {t["Key"]: t["Value"] for t in desc.get("Tags", [])}
    assert "aws:reserved" not in tags, f"reserved tag key leaked into {tags!r}"

    # Positive control: a non-reserved tag key on the same secret is accepted, so the
    # rejection above is shown to be specific to the "aws:" prefix rather than every
    # TagResource call being refused.
    sm.tag_resource(SecretId=name, Tags=[{"Key": "team", "Value": "platform"}])
    control_tags = _poll_for_tag(sm, name, "team", "platform")
    assert control_tags.get("team") == "platform", f"expected control tag applied, got {control_tags!r}"


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
