"""cdk-machine-image-from-ssm-parameter-rejected-for-an-unknown-parameter."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "cdk-machine-image-from-ssm-parameter-rejected-for-an-unknown-parameter"
GROUP = "cdk-context-provider"
SERVICES = ["ec2", "ssm"]

_SYNTH_TIMEOUT_S = 180.0
_APP = Path(__file__).parent / "deployments" / "cdk-machine-image-ssm-param"
_REAL_PARAM = "/aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64"


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c5",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """MachineImage.from_ssm_parameter(cached_in_context=True) on a public /aws/service/
    parameter bakes the value GetParameter reads as a literal; for a parameter no account holds
    `cdk synth` exits non-zero with the provider's exact error line and caches nothing."""
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")
    ctx.verify_account_safety()
    ssm = ctx.client("ssm")
    ec2 = ctx.client("ec2")
    acct = ctx.account

    assert (_APP / "app.py").is_file() and (_APP / "cdk.json").is_file(), (
        f"the CDK app this check synthesizes is missing from disk: expected app.py and cdk.json "
        f"under {_APP}, found "
        f"{sorted(p.name for p in _APP.iterdir()) if _APP.is_dir() else 'no such dir'}"
    )

    expected_value = ssm.get_parameter(Name=_REAL_PARAM)["Parameter"]["Value"]
    images = ec2.describe_images(ImageIds=[expected_value])["Images"]
    assert len(images) == 1, (
        f"DescribeImages({expected_value!r}) (the public parameter's own value) returned "
        f"{len(images)} images, expected exactly 1 - the parameter must name a real AMI"
    )

    bogus_param = "/aws/service/ami-amazon-linux-latest/" + ctx.unique_name(
        "sim2real-no-such-param-"
    )
    got_api = _error(lambda: ssm.get_parameter(Name=bogus_param))
    assert got_api == ("ParameterNotFound", ""), (
        f"GetParameter({bogus_param!r}): expected ('ParameterNotFound', ''), got {got_api!r}"
    )

    qualifier = ctx.unique_name("q")[:10]
    stack = ctx.unique_name("sim2real-cdkamissm-")
    work = _stage(ctx, _APP)

    # Positive control first.
    rc, out = _synth(ctx, work, qualifier, stack, acct, _REAL_PARAM)
    assert rc == 0, (
        f"the POSITIVE CONTROL failed: `cdk synth` with parameter {_REAL_PARAM!r} exited "
        f"{rc}, expected 0. Output tail: {out[-800:]!r}"
    )
    context = json.loads((work / "cdk.context.json").read_text())
    key = f"ssm:account={acct}:parameterName={_REAL_PARAM}:region={ctx.region}"
    assert key in context, f"cdk.context.json holds keys {sorted(context)!r}, expected {key!r}"
    assert context[key] == expected_value, (
        f"the ssm-parameter provider resolved {context[key]!r}, expected GetParameter's own "
        f"value {expected_value!r}"
    )
    template = json.loads((work / "cdk.out" / f"{stack}.template.json").read_text())
    assert template["Outputs"]["ImageId"]["Value"] == expected_value, (
        f"the control template's ImageId output is {template['Outputs']['ImageId']['Value']!r}, "
        f"expected the literal resolved value {expected_value!r}; cached_in_context=True must "
        f"bake a literal, never a {{resolve:ssm:...}} dynamic reference"
    )

    # Negative: the parameter does not exist under /aws/service/.
    _clear_assembly(work)
    rc2, out2 = _synth(ctx, work, qualifier, stack, acct, bogus_param)
    assert rc2 != 0, (
        f"`cdk synth` exited 0 for parameter {bogus_param!r}, which this account does not hold. "
        f"Output tail: {out2[-500:]!r}"
    )
    want_lines = [
        f"[Error at /{stack}] SSM parameter not available in account {acct}, region "
        f"{ctx.region}: {bogus_param}"
    ]
    got_lines = _error_lines(work, stack)
    assert got_lines == want_lines, (
        f"assembly error annotations for {bogus_param!r}: expected {want_lines!r}, got {got_lines!r}"
    )
    denied_context = json.loads((work / "cdk.context.json").read_text())
    assert [k for k in denied_context if bogus_param in k] == [], (
        f"an ssm: context entry naming {bogus_param!r} was cached despite the lookup being "
        f"refused: {sorted(denied_context)!r}"
    )

    # Control, repeated: the real parameter still resolves after the refused arm.
    _clear_assembly(work)
    rc3, out3 = _synth(ctx, work, qualifier, stack, acct, _REAL_PARAM)
    assert rc3 == 0, (
        f"control: `cdk synth` with {_REAL_PARAM!r} exited {rc3} after the refused arm, "
        f"expected 0. Output tail: {out3[-800:]!r}"
    )
    again = json.loads((work / "cdk.context.json").read_text())
    assert again[key] == expected_value, (
        f"control: re-running the real-parameter lookup resolved {again.get(key)!r}, expected "
        f"{expected_value!r}"
    )


def _error(fn) -> tuple[str | None, str | None]:
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _error_lines(work: Path, stack: str) -> list[str]:
    """The cloud assembly's error annotations for the stack's constructs, as ``[Error at <path>] <msg>``.

    Read from the assembly the synth wrote, not the CLI output, whose layout varies by CLI version.
    """
    out = work / "cdk.out"
    entries: dict[str, list] = dict(
        json.loads((out / "manifest.json").read_text())["artifacts"].get(stack, {}).get("metadata")
        or {}
    )
    side = out / f"{stack}.metadata.json"
    if side.is_file():
        entries.update(json.loads(side.read_text()))
    return [
        f"[Error at {path}] {e['data']}"
        for path, items in sorted(entries.items())
        for e in items
        if e.get("type") == "aws:cdk:error"
    ]


def _stage(ctx, app_dir: Path) -> Path:
    """Copy the CDK app to a temp workdir so cdk.out and cdk.context.json stay out of the checkout."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkamissm-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(app_dir, work, dirs_exist_ok=True)
    return work


def _clear_assembly(work: Path) -> None:
    """Remove the cloud assembly and context cache so the next synth performs the lookup again."""
    shutil.rmtree(work / "cdk.out", ignore_errors=True)
    (work / "cdk.context.json").unlink(missing_ok=True)


_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s so the wait fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _synth(
    ctx, work: Path, qualifier: str, stack: str, acct: str, param_name: str
) -> tuple[int, str]:
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = acct
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["PARAM_NAME"] = param_name
    cmd = [
        "cdk",
        "synth",
        "--quiet",
        "--ci",
        "--no-version-reporting",
        "--app",
        f"{sys.executable} app.py",
    ]
    timeout_s = _budget_s(ctx, _SYNTH_TIMEOUT_S)
    try:
        r = subprocess.run(
            cmd, cwd=work, env=env, capture_output=True, text=True, timeout=timeout_s
        )
    except subprocess.TimeoutExpired:
        if _budget_spent(ctx):
            raise TimeoutError("`cdk synth`: the run budget ended first; not graded") from None
        raise AssertionError(f"`cdk synth` did not finish within {timeout_s}s") from None
    return r.returncode, _ANSI.sub("", r.stdout + r.stderr)


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
