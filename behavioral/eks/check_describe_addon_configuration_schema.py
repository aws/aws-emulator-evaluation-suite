"""describe-addon-configuration-schema."""
from __future__ import annotations

import json

from botocore.exceptions import ClientError

from behavioral_harness import tags


def _expect_error(fn):
    """Call fn, require that it raises, return (ErrorCode, Message)."""
    try:
        fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code", ""), err.get("Message", "")
    raise AssertionError("expected the call to fail, but it succeeded")

CHECK = "describe-addon-configuration-schema"
GROUP = 'metadata'
SERVICES = ['eks']

@tags("axis:happy-path", "cap:c5", "concern:negative-classes", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeAddonConfiguration returns a parseable JSON Schema for a real addon version, and rejects a version that does not exist."""
    c = ctx.client("eks")
    catalog = c.describe_addon_versions(addonName="vpc-cni", maxResults=1)
    version_info = catalog["addons"][0]["addonVersions"][0]
    version = version_info["addonVersion"]

    resp = c.describe_addon_configuration(
        addonName="vpc-cni", addonVersion=version
    )
    assert resp["addonName"] == "vpc-cni", resp
    assert resp["addonVersion"] == version, resp
    schema = json.loads(resp["configurationSchema"])
    assert isinstance(schema, dict) and schema, schema
    # The catalogue's own requiresConfiguration flag for this exact version
    # says whether the schema should carry real structure, not just be non-empty.
    if version_info.get("requiresConfiguration"):
        assert schema.get("properties") or schema.get("$ref"), (
            f"{version} is flagged requiresConfiguration but the schema is bare: {schema}"
        )

    missing_version = "v9.99.99-eksbuild.99"
    code, message = _expect_error(
        lambda: c.describe_addon_configuration(
            addonName="vpc-cni", addonVersion=missing_version
        )
    )
    # An add-on version that is not in the catalogue is a missing *resource*,
    # not a malformed parameter.
    assert code == "ResourceNotFoundException", code
    expected = (
        f"Schema not found for requested addonName=[vpc-cni] and addonVersion=[{missing_version}]"
    )
    assert message == expected, message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
