"""delete-layer-version."""

from __future__ import annotations

import io
import textwrap
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags


CHECK = "delete-layer-version"
GROUP = 'layers'
SERVICES = ['lambda']


def _make_zip(code, filename="index.py"):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr(filename, textwrap.dedent(code))
    return buf.getvalue()


def _client_error(fn):
    """(code, message) of a call that must be refused; raises if the call succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be rejected, but it succeeded: {result!r}")


@tags("axis:rejection", "cap:c1", "concern:negative-classes", "plane:control")
def run(ctx) -> None:
    """DeleteLayerVersion → GetLayerVersion returns 404, and the dead version also rejects a
    mutation (AddLayerVersionPermission), proving it is gone and unusable, not merely unlisted."""
    lam = ctx.client("lambda")
    layer_name = ctx.unique_name("sim2real-behav-layer-")
    published = lam.publish_layer_version(
        LayerName=layer_name,
        Content={"ZipFile": _make_zip("Y = 1\n", "python/y.py")},
        CompatibleRuntimes=["python3.12"],
    )
    version = published["Version"]

    lam.delete_layer_version(LayerName=layer_name, VersionNumber=version)

    read_code, read_code_msg = _client_error(
        lambda: lam.get_layer_version(LayerName=layer_name, VersionNumber=version)
    )
    assert read_code == "ResourceNotFoundException", (
        f"expected GetLayerVersion on a deleted version to 404, got {read_code}"
    )
    expected_read_code_msg = "The resource you requested does not exist."
    assert read_code_msg == expected_read_code_msg, (
        f"expected message {expected_read_code_msg!r}, got {read_code_msg!r}"
    )

    account = ctx.account
    mutate_code, mutate_code_msg = _client_error(
        lambda: lam.add_layer_version_permission(
            LayerName=layer_name,
            VersionNumber=version,
            StatementId="sim2real-behav-dead-version",
            Action="lambda:GetLayerVersion",
            Principal=account,
        )
    )
    assert mutate_code == "ResourceNotFoundException", (
        f"expected AddLayerVersionPermission on a deleted version to 404, got {mutate_code}"
    )
    expected_mutate_code_msg = f"Layer version {published['LayerVersionArn']} does not exist."
    assert mutate_code_msg == expected_mutate_code_msg, (
        f"expected message {expected_mutate_code_msg!r}, got {mutate_code_msg!r}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
