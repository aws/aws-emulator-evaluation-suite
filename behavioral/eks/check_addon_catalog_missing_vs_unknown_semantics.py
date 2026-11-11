"""addon-catalog-missing-vs-unknown-semantics."""
from __future__ import annotations

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

CHECK = "addon-catalog-missing-vs-unknown-semantics"
GROUP = 'error-semantics'
SERVICES = ['eks']

@tags("axis:rejection", "cap:c5", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """A *filter* that matches nothing returns an empty list, but a *lookup* of the same unknown add-on raises ResourceNotFoundException -- two different contracts over the same catalogue."""
    c = ctx.client("eks")
    unknown = "sim2real-not-a-real-addon"

    # Positive control: a real add-on with a real version resolves on both
    # the filter and the lookup operation, proving neither one is a blanket
    # failure -- the not-found below is specific to the unknown subject.
    real = c.describe_addon_versions(addonName="vpc-cni")["addons"]
    assert real and real[0]["addonName"] == "vpc-cni", real
    real_version = real[0]["addonVersions"][0]["addonVersion"]
    conf = c.describe_addon_configuration(addonName="vpc-cni", addonVersion=real_version)
    assert conf["addonName"] == "vpc-cni", conf
    assert conf["addonVersion"] == real_version, conf

    # Filter semantics: no match is an empty result, not an error.
    resp = c.describe_addon_versions(addonName=unknown)
    assert resp.get("addons", []) == [], resp

    # Lookup semantics on the same unknown name: a hard not-found.
    unknown_version = "v1.0.0-eksbuild.1"
    code, message = _expect_error(
        lambda: c.describe_addon_configuration(
            addonName=unknown, addonVersion=unknown_version
        )
    )
    assert code == "ResourceNotFoundException", code
    assert message == (
        f"Schema not found for requested addonName=[{unknown}] and addonVersion=[{unknown_version}]"
    ), message


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
