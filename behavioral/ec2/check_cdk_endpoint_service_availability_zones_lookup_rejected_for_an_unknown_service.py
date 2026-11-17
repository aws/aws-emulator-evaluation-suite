"""cdk-endpoint-service-availability-zones-lookup-rejected-for-an-unknown-service."""

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

CHECK = "cdk-endpoint-service-availability-zones-lookup-rejected-for-an-unknown-service"
GROUP = "cdk-context-provider"
SERVICES = ["ec2"]

_SYNTH_TIMEOUT_S = 180.0
_APP = Path(__file__).parent / "deployments" / "cdk-endpoint-service-azs"


@tags(
    "axis:rejection",
    "cap:c3",
    "cap:c5",
    "concern:representation",
    "concern:negative-classes",
    "plane:control",
)
def run(ctx) -> None:
    """lookup_supported_azs=True keeps an interface endpoint's subnets to the default VPC's public
    subnets in the AZs DescribeVpcEndpointServices reports for a real service; for an unknown
    service `cdk synth` exits non-zero with the provider's exact error line and keeps them all."""
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

    real_service = f"com.amazonaws.{ctx.region}.execute-api"
    details = ec2.describe_vpc_endpoint_services(ServiceNames=[real_service])["ServiceDetails"]
    assert len(details) == 1, (
        f"DescribeVpcEndpointServices({real_service!r}) returned {len(details)} service details, "
        f"expected exactly 1 - this check needs a service this account's region really publishes"
    )
    expected_azs = sorted(details[0]["AvailabilityZones"])

    public_by_az = _default_vpc_public_subnets(ec2)
    all_public = sorted(sid for sids in public_by_az.values() for sid in sids)
    control_expected = sorted(
        sid for az, sids in public_by_az.items() if az in expected_azs for sid in sids
    )

    bogus_service = f"com.amazonaws.{ctx.region}.{ctx.unique_name('sim2real-bogus-svc-')}"
    want_api = (
        "InvalidServiceName",
        f"The Vpc Endpoint Service '{bogus_service}' does not exist",
    )
    got_api = _error(lambda: ec2.describe_vpc_endpoint_services(ServiceNames=[bogus_service]))
    assert got_api == want_api, (
        f"DescribeVpcEndpointServices({bogus_service!r}): expected {want_api!r}, got {got_api!r}"
    )

    qualifier = ctx.unique_name("q")[:10]
    stack = ctx.unique_name("sim2real-cdkepaz-")
    work = _stage(ctx, _APP)

    # Positive control first.
    rc, out = _synth(ctx, work, qualifier, stack, acct, real_service)
    assert rc == 0, (
        f"the POSITIVE CONTROL failed: `cdk synth` for the real service {real_service!r} exited "
        f"{rc}, expected 0. Output tail: {out[-800:]!r}"
    )
    context = json.loads((work / "cdk.context.json").read_text())
    key = (
        f"endpoint-service-availability-zones:account={acct}:region={ctx.region}:"
        f"serviceName={real_service}"
    )
    assert key in context, f"cdk.context.json holds keys {sorted(context)!r}, expected {key!r}"
    assert sorted(context[key]) == expected_azs, (
        f"the endpoint-service-availability-zones provider resolved {sorted(context[key])!r} "
        f"for {real_service!r}, expected {expected_azs!r} from DescribeVpcEndpointServices"
    )
    control_templates = sorted((work / "cdk.out").glob("*.template.json"))
    assert len(control_templates) == 1, (
        f"the control arm wrote {len(control_templates)} templates, expected exactly 1"
    )
    control_subnets = sorted(_endpoint_subnet_ids(json.loads(control_templates[0].read_text())))
    assert control_subnets == control_expected, (
        f"the control arm's VPCEndpoint declares SubnetIds {control_subnets!r}, expected the "
        f"default VPC's public subnets in {expected_azs!r}: {control_expected!r}"
    )

    # Negative: no VPC endpoint service exists under this name.
    _clear_assembly(work)
    rc2, out2 = _synth(ctx, work, qualifier, stack, acct, bogus_service)
    assert rc2 != 0, (
        f"`cdk synth` exited 0 for endpoint service {bogus_service!r}, which this account's "
        f"region does not publish. Output tail: {out2[-500:]!r}"
    )
    want_lines = [f"[Error at /{stack}/Ep] {want_api[1]}"]
    got_lines = _error_lines(work, stack)
    assert got_lines == want_lines, (
        f"assembly error annotations for {bogus_service!r}: expected {want_lines!r}, got {got_lines!r}"
    )
    denied_context = json.loads((work / "cdk.context.json").read_text())
    assert [k for k in denied_context if bogus_service in k] == [], (
        f"a context entry naming {bogus_service!r} was cached despite the lookup being refused: "
        f"{sorted(denied_context)!r}"
    )
    denied_templates = sorted((work / "cdk.out").glob("*.template.json"))
    assert len(denied_templates) == 1, (
        f"the refused arm wrote {len(denied_templates)} templates, expected exactly 1"
    )
    denied_subnets = sorted(_endpoint_subnet_ids(json.loads(denied_templates[0].read_text())))
    assert denied_subnets == all_public, (
        f"the refused arm's VPCEndpoint declares SubnetIds {denied_subnets!r}, expected every "
        f"public subnet of the default VPC {all_public!r}"
    )

    # Control, repeated: the real service still resolves after the refused arm.
    _clear_assembly(work)
    rc3, out3 = _synth(ctx, work, qualifier, stack, acct, real_service)
    assert rc3 == 0, (
        f"control: `cdk synth` for {real_service!r} exited {rc3} after the refused arm, "
        f"expected 0. Output tail: {out3[-800:]!r}"
    )
    again = json.loads((work / "cdk.context.json").read_text())
    assert sorted(again.get(key, [])) == expected_azs, (
        f"control: re-running the real-service lookup resolved {sorted(again.get(key, []))!r}, "
        f"expected {expected_azs!r}"
    )


def _error(fn) -> tuple[str | None, str | None]:
    """(code, message) of the ClientError ``fn`` raises; an unexpected success raises too."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message")
    raise AssertionError(f"expected the call to be refused, but it succeeded: {result!r}")


def _default_vpc_public_subnets(ec2) -> dict[str, list[str]]:
    """The default VPC's public subnets by AZ: a subnet whose route table (its own, else the main
    one) routes to an internet gateway."""
    vpcs = (
        ec2.get_paginator("describe_vpcs")
        .paginate(Filters=[{"Name": "is-default", "Values": ["true"]}])
        .build_full_result()["Vpcs"]
    )
    assert len(vpcs) == 1, f"expected exactly one default VPC, got {[v['VpcId'] for v in vpcs]!r}"
    vpc_id = vpcs[0]["VpcId"]
    vpc_filter = [{"Name": "vpc-id", "Values": [vpc_id]}]
    subnets = (
        ec2.get_paginator("describe_subnets")
        .paginate(Filters=vpc_filter)
        .build_full_result()["Subnets"]
    )
    tables = (
        ec2.get_paginator("describe_route_tables")
        .paginate(Filters=vpc_filter)
        .build_full_result()["RouteTables"]
    )
    main = [t for t in tables if any(a.get("Main") for a in t.get("Associations", []))]
    assert len(main) == 1, f"VPC {vpc_id!r} has {len(main)} main route tables, expected exactly 1"
    out: dict[str, list[str]] = {}
    for s in subnets:
        sid = s["SubnetId"]
        own = [
            t for t in tables if any(a.get("SubnetId") == sid for a in t.get("Associations", []))
        ]
        table = own[0] if own else main[0]
        if any(r.get("GatewayId", "").startswith("igw-") for r in table["Routes"]):
            out.setdefault(s["AvailabilityZone"], []).append(sid)
    return out


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


def _endpoint_subnet_ids(template: dict) -> list[str]:
    """SubnetIds of the template's single AWS::EC2::VPCEndpoint resource."""
    endpoints = [v for v in template["Resources"].values() if v["Type"] == "AWS::EC2::VPCEndpoint"]
    assert len(endpoints) == 1, f"template has {len(endpoints)} VPC endpoints, expected exactly 1"
    return list(endpoints[0]["Properties"]["SubnetIds"])


def _stage(ctx, app_dir: Path) -> Path:
    """Copy the CDK app to a temp workdir so cdk.out and cdk.context.json stay out of the checkout."""
    work = Path(tempfile.mkdtemp(prefix="sim2real-cdkepaz-"))
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
    ctx, work: Path, qualifier: str, stack: str, acct: str, service_name: str
) -> tuple[int, str]:
    ctx.verify_account_safety()
    env = ctx.subprocess_env()
    env["CDK_DEFAULT_REGION"] = ctx.region
    env["CDK_DEFAULT_ACCOUNT"] = acct
    env["Q"] = qualifier
    env["STACK_NAME"] = stack
    env["SERVICE_NAME"] = service_name
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
