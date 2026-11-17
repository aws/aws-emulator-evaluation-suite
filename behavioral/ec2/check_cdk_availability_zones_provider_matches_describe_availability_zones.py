"""cdk-availability-zones-provider-matches-describe-availability-zones."""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from behavioral_harness import tags

CHECK = "cdk-availability-zones-provider-matches-describe-availability-zones"
GROUP = "cdk-context-provider"
SERVICES = ["ec2"]

_SYNTH_TIMEOUT_S = 180.0
_APP = Path(__file__).parent / "deployments" / "cdk-availability-zones"


@tags("axis:happy-path", "cap:c3", "cap:c5", "concern:representation", "plane:control")
def run(ctx) -> None:
    """A stack with an explicit account/region reads Stack.availability_zones from the
    availability-zones context provider, which matches DescribeAvailabilityZones' available
    zones for the same account and region, in the order the API returns them."""
    from fidelity_tests_runner import require_tools

    require_tools("cdk", "node")
    ctx.verify_account_safety()
    ec2 = ctx.client("ec2")
    acct = ctx.account

    assert (_APP / "app.py").is_file() and (_APP / "cdk.json").is_file(), (
        f"the CDK app this check synthesizes is missing from disk: expected app.py and cdk.json "
        f"under {_APP}, found "
        f"{sorted(p.name for p in _APP.iterdir()) if _APP.is_dir() else 'no such dir'}"
    )

    raw = ec2.describe_availability_zones()["AvailabilityZones"]
    expected = [z["ZoneName"] for z in raw if z["State"] == "available"]
    assert expected, f"this region reports no available AZs in {raw!r}"

    qualifier = ctx.unique_name("q")[:10]
    stack = ctx.unique_name("sim2real-cdkazp-")
    work = _stage(ctx, _APP)

    rc, out = _synth(ctx, work, qualifier, stack, acct)
    assert rc == 0, f"`cdk synth` exited {rc}, expected 0. Output tail: {out[-800:]!r}"

    context = json.loads((work / "cdk.context.json").read_text())
    key = f"availability-zones:account={acct}:region={ctx.region}"
    assert key in context, (
        f"cdk.context.json holds keys {sorted(context)!r}, expected {key!r} among them"
    )
    assert context[key] == expected, (
        f"the availability-zones provider resolved {context[key]!r}, expected "
        f"{expected!r} from DescribeAvailabilityZones filtered to State == 'available'"
    )

    template = json.loads((work / "cdk.out" / f"{stack}.template.json").read_text())
    got_output = template["Outputs"]["Azs"]["Value"].split(",")
    assert got_output == expected, (
        f"the synthesized template's Azs output is {got_output!r}, expected {expected!r}; a "
        f"token or placeholder here means the provider did not resolve before synth"
    )


def _stage(ctx, app_dir: Path) -> Path:
    """Copy the CDK app to a temp workdir so cdk.out and cdk.context.json stay out of the checkout."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkazp-"))
    ctx.on_cleanup(lambda: shutil.rmtree(work, ignore_errors=True))
    shutil.copytree(app_dir, work, dirs_exist_ok=True)
    return work


def _budget_s(ctx, cap_s):
    """A wait's timeout: cap_s, bounded by the runner's remaining time less 5 s so the wait fails
    with its own message."""
    left = ctx.time_left()
    return cap_s if left is None else max(1.0, min(cap_s, left - 5.0))


def _budget_spent(ctx):
    """True when the runner's remaining time, not the wait's own deadline, ended a capped wait."""
    left = ctx.time_left()
    return left is not None and left <= 6.0


def _synth(ctx, work: Path, qualifier: str, stack: str, acct: str) -> tuple[int, str]:
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = acct
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
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
    return r.returncode, r.stdout + r.stderr


if __name__ == "__main__":
    from fidelity_tests_runner import main

    main(run)
