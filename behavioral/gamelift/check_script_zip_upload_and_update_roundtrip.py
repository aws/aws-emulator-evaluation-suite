"""script-zip-upload-and-update-roundtrip."""
from __future__ import annotations

import io
import zipfile

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "script-zip-upload-and-update-roundtrip"
GROUP = "data-plane"
SERVICES = ["gamelift"]


@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """CreateScript with a ZipFile stores a nonzero SizeOnDisk, UpdateScript with a larger zip grows it as Describe
    shows, and after DeleteScript both DescribeScript and UpdateScript fail with NotFoundException and its exact
    message.
    """
    gl = ctx.client("gamelift")
    name = ctx.unique_name("sim2real-script-")

    small_zip = _make_zip({"main.js": "exports.handler = () => 1;"})
    created = gl.create_script(
        Name=name,
        ZipFile=small_zip,
        # CreateScript requires a supported runtime; omitting it, or naming a deprecated one, is refused.
        NodeJsVersion="24.x",
        Tags=[{"Key": "env", "Value": "sim2real"}, {"Key": "owner", "Value": "behavioral"}],
    )["Script"]
    script_id = created["ScriptId"]

    def _cleanup():
        try:
            gl.delete_script(ScriptId=script_id)
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") != "NotFoundException":
                raise

    ctx.on_cleanup(_cleanup)

    assert created["SizeOnDisk"] > 0, f"expected nonzero SizeOnDisk on create, got {created['SizeOnDisk']}"
    first_size = created["SizeOnDisk"]

    described = gl.describe_script(ScriptId=script_id)["Script"]
    assert described["SizeOnDisk"] == first_size, (
        f"expected describe to echo the created SizeOnDisk {first_size}, got {described['SizeOnDisk']}"
    )

    bigger_zip = _make_zip(
        {"main.js": "exports.handler = () => 1;", "padding.txt": "x" * 50_000}
    )
    updated = gl.update_script(ScriptId=script_id, ZipFile=bigger_zip)["Script"]
    assert updated["SizeOnDisk"] > first_size, (
        f"expected UpdateScript with a larger ZipFile to grow SizeOnDisk past {first_size}, "
        f"got {updated['SizeOnDisk']}"
    )

    described_after = gl.describe_script(ScriptId=script_id)["Script"]
    assert described_after["SizeOnDisk"] == updated["SizeOnDisk"], (
        f"expected an independent describe to reflect the update's SizeOnDisk "
        f"{updated['SizeOnDisk']}, got {described_after['SizeOnDisk']}"
    )
    assert described_after["SizeOnDisk"] > first_size, (
        f"expected the post-update size {described_after['SizeOnDisk']} to exceed the "
        f"original {first_size}"
    )

    gl.delete_script(ScriptId=script_id)

    expected_message = f"Script ({script_id}) not found."
    code, message = _error(lambda: gl.describe_script(ScriptId=script_id))
    assert code == "NotFoundException", f"expected NotFoundException describing a deleted script, got {code}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"

    code, message = _error(lambda: gl.update_script(ScriptId=script_id, ZipFile=bigger_zip))
    assert code == "NotFoundException", f"expected NotFoundException updating a deleted script, got {code}"
    assert message == expected_message, f"expected message {expected_message!r}, got {message!r}"


def _error(fn):
    """Call fn(); return the (code, message) of the ClientError it raises. A success raises."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded and returned {result!r}")


def _make_zip(files: dict) -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for filename, content in files.items():
            zf.writestr(filename, content)
    return buf.getvalue()


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
