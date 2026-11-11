"""public-parameter-reference-data-readable-not-owned."""
from __future__ import annotations

import re
import time

from botocore.exceptions import ClientError

from behavioral_harness import tags

CHECK = "public-parameter-reference-data-readable-not-owned"
GROUP = 'state-machine'
SERVICES = ['ssm']

# AWS-owned public parameter namespace. Read-only reference data — nothing here is
# created, modified, or deleted by this check.
_PUBLIC_PATH = "/aws/service/ami-amazon-linux-latest"
_AMI_RE = re.compile(r"^ami-[0-9a-f]{8,17}$")


def _error(fn):
    """Return the (code, message) of the ClientError fn raises; raise if fn succeeds."""
    try:
        result = fn()
    except ClientError as exc:
        err = exc.response.get("Error", {})
        return err.get("Code"), err.get("Message") or ""
    raise AssertionError(f"the call was expected to be refused but it succeeded: {result!r}")


def _param_name(ctx, suffix=""):
    # SSM requires a leading '/' for any hierarchical (slash-containing) name.
    return "/" + ctx.unique_name("sim2real-behav-" + suffix)


def _track_parameter(ctx, ssm, name):
    ctx.on_cleanup(lambda: ssm.delete_parameter(Name=name))
    return name


# DescribeParameters is eventually consistent after PutParameter.
def _poll(probe, predicate, timeout_s=90, interval_s=3.0):
    deadline = time.monotonic() + timeout_s
    while True:
        last = probe()
        if predicate(last):
            return last
        if time.monotonic() >= deadline:
            raise AssertionError(
                f"condition not met within {timeout_s}s (last observed: {last!r})"
            )
        time.sleep(interval_s)


def _drain_public(ssm, path, pages=3):
    """Page a public parameter path. MaxResults caps at 10 for GetParametersByPath."""
    found = []
    token = None
    for _ in range(pages):
        kwargs = {"Path": path, "Recursive": True, "MaxResults": 10}
        if token is not None:
            kwargs["NextToken"] = token
        resp = ssm.get_parameters_by_path(**kwargs)
        found.extend(resp["Parameters"])
        token = resp.get("NextToken")
        if not token:
            break
    return found


def _drain_inventory(ssm):
    """Page the unfiltered DescribeParameters to exhaustion and return the names in order.

    Unfiltered, it omits the AWS public namespace, which a Path- or Name-filtered call includes.
    """
    names = []
    token = None
    for _ in range(20):
        kwargs = {"MaxResults": 50}
        if token is not None:
            kwargs["NextToken"] = token
        page = ssm.describe_parameters(**kwargs)
        names.extend(p["Name"] for p in page["Parameters"])
        token = page.get("NextToken")
        if not token:
            return names
    raise AssertionError("the unfiltered DescribeParameters drain did not terminate")


@tags("axis:happy-path", "cap:c2", "cap:c5", "concern:data-plane", "concern:negative-classes", "concern:representation", "dp:api", "plane:data")
def run(ctx) -> None:
    """Public parameters under /aws/service/ resolve to real AMI ids yet are not owned: their ARNs
    have an empty account field, the unfiltered inventory omits them, and writes are refused.
    """

    ssm = ctx.client("ssm")

    public = _drain_public(ssm, _PUBLIC_PATH)
    assert len(public) >= 5, (
        f"{_PUBLIC_PATH} must expose AWS's published Amazon Linux AMI parameters; got "
        f"{len(public)}: {[p['Name'] for p in public]}"
    )
    for param in public:
        assert param["Name"].startswith(_PUBLIC_PATH + "/"), (
            f"a path read must only return names beneath the path, got {param['Name']!r}"
        )
        assert param["Type"] == "String", (
            f"public AMI parameters are String, got {param['Type']!r} for {param['Name']}"
        )
        assert "Value" in param and param["Value"], param
        assert param["ARN"].startswith("arn:"), (
            f"a public parameter must still report an ARN, got {param.get('ARN')!r}"
        )

    ami_params = [p for p in public if _AMI_RE.match(p["Value"])]
    assert len(ami_params) >= 3, (
        "most parameters under this path resolve to a concrete AMI id matching "
        f"^ami-[0-9a-f]{{8,17}}$; only {len(ami_params)} of {len(public)} did: "
        f"{[(p['Name'], p['Value']) for p in public]}"
    )

    # A concrete, derived (not hardcoded) selection: the current x86_64 AL2023 AMI.
    candidates = [
        p
        for p in ami_params
        if "al2023" in p["Name"] and "x86_64" in p["Name"] and "minimal" not in p["Name"]
    ]
    assert candidates, (
        "expected a non-minimal al2023 x86_64 entry under the path, got "
        f"{[p['Name'] for p in ami_params]}"
    )
    chosen = candidates[0]

    single = ssm.get_parameter(Name=chosen["Name"])["Parameter"]
    assert single["Value"] == chosen["Value"], (
        f"GetParameter and GetParametersByPath disagree for {chosen['Name']}: "
        f"{single['Value']!r} vs {chosen['Value']!r}"
    )
    assert _AMI_RE.match(single["Value"]), single
    assert single["Type"] == "String", single
    assert single["Version"] >= 1, (
        f"public parameters are versioned reference data, got Version {single.get('Version')!r}"
    )
    assert "LastModifiedDate" in single, (
        f"a resolved parameter must report LastModifiedDate, got keys {sorted(single)}"
    )

    batch = ssm.get_parameters(Names=[chosen["Name"]])
    assert batch["InvalidParameters"] == [], (
        f"GetParameters must resolve a public parameter, got {batch['InvalidParameters']}"
    )
    assert [p["Value"] for p in batch["Parameters"]] == [chosen["Value"]], batch

    # A filtered DescribeParameters does not hide the public namespace, so non-ownership shows in
    # two other places. (1) A public parameter's ARN has an empty account field.
    for param in public:
        arn_parts = param["ARN"].split(":", 5)
        assert arn_parts[:3] == ["arn", "aws", "ssm"], param["ARN"]
        assert arn_parts[3] == ctx.region, (
            f"a public parameter's ARN must be regional, got {param['ARN']!r}"
        )
        assert arn_parts[4] == "", (
            f"a public parameter is not owned by any account, so its ARN's account field must be "
            f"EMPTY, got {arn_parts[4]!r} in {param['ARN']!r}"
        )
        assert arn_parts[5] == "parameter" + param["Name"], (
            f"the ARN resource must be 'parameter' + the parameter's own name, got "
            f"{arn_parts[5]!r} for {param['Name']!r}"
        )

    described_at_public_path = ssm.describe_parameters(
        ParameterFilters=[
            {"Key": "Path", "Option": "Recursive", "Values": [_PUBLIC_PATH]}
        ]
    )["Parameters"]
    assert described_at_public_path, (
        "asked for the public path explicitly, DescribeParameters describes AWS public "
        "parameters (measured on real AWS, us-west-2); it returned nothing"
    )
    assert all(p["Name"].startswith(_PUBLIC_PATH + "/") for p in described_at_public_path), (
        f"the Path filter must confine the result to the path, got "
        f"{[p['Name'] for p in described_at_public_path]}"
    )
    for p in described_at_public_path:
        # Public parameters carry the same inventory metadata as owned Standard-tier ones.
        assert p["Tier"] == "Standard", (p["Name"], p.get("Tier"))
        assert p["DataType"] == "text", (p["Name"], p.get("DataType"))
        assert p["Policies"] == [], (p["Name"], p.get("Policies"))
        assert p["Version"] >= 1, (p["Name"], p.get("Version"))
        assert p["ARN"].split(":", 5)[4] == "", p["ARN"]
    by_name = ssm.describe_parameters(
        ParameterFilters=[
            {"Key": "Name", "Option": "Equals", "Values": [chosen["Name"]]}
        ]
    )["Parameters"]
    assert [p["Name"] for p in by_name] == [chosen["Name"]], (
        f"a Name/Equals filter must describe the public parameter {chosen['Name']}, got {by_name}"
    )

    # (2) The unfiltered DescribeParameters enumerates only what the account owns.
    inventory = _drain_inventory(ssm)
    assert not [n for n in inventory if n.startswith("/aws/")], (
        "the unfiltered DescribeParameters enumerates only account-owned parameters and must "
        f"not include the AWS public namespace, got {[n for n in inventory if n.startswith('/aws/')]}"
    )

    # Positive control: the same filter forms find an owned parameter, so the empty results
    # above are not empty by construction.
    own_base = _param_name(ctx, "refdata-")
    own_name = f"{own_base}/leaf"
    _track_parameter(ctx, ssm, own_name)
    ssm.put_parameter(
        Name=own_name,
        Value="sim2real-behav-owned",
        Type="String",
        Tags=[{"Key": "sim2real", "Value": CHECK}],
    )

    found_by_path = _poll(
        lambda: ssm.describe_parameters(
            ParameterFilters=[
                {"Key": "Path", "Option": "Recursive", "Values": [own_base]}
            ]
        )["Parameters"],
        lambda got: len(got) == 1,
    )
    # DescribeParameters reports a hierarchical name exactly as submitted, leading slash included.
    assert found_by_path[0]["Name"] == own_name, (
        f"the Path/Recursive filter must find the account's own parameter under its exact name, "
        f"got {found_by_path}"
    )
    found_by_name = ssm.describe_parameters(
        ParameterFilters=[{"Key": "Name", "Option": "Equals", "Values": [own_name]}]
    )["Parameters"]
    assert [p["Name"] for p in found_by_name] == [own_name], (
        f"the Name/Equals filter must find the account's own parameter, got {found_by_name}"
    )
    # Re-drained, the inventory contains the owned parameter and still no /aws/ name.
    inventory_now = _poll(
        lambda: _drain_inventory(ssm),
        lambda names: own_name in names,
    )
    assert not [n for n in inventory_now if n.startswith("/aws/")], (
        "the account inventory must still exclude the AWS public namespace, got "
        f"{[n for n in inventory_now if n.startswith('/aws/')]}"
    )
    # The ARN account slot that is empty for a public parameter carries the owner's 12-digit id.
    own_arn = ssm.get_parameter(Name=own_name)["Parameter"]["ARN"]
    own_parts = own_arn.split(":", 5)
    assert own_parts[:4] == ["arn", "aws", "ssm", ctx.region], own_arn
    assert own_parts[4] == ctx.account, (
        f"an account-owned parameter's ARN must name the owning account {ctx.account!r}, got "
        f"{own_arn!r}"
    )
    assert own_parts[5] == "parameter" + own_name, own_arn
    assert chosen["ARN"].split(":", 5)[4] == "", chosen["ARN"]

    # An account-owned path read must not leak the public namespace.
    owned_path_read = _poll(
        lambda: ssm.get_parameters_by_path(Path=own_base, Recursive=True)["Parameters"],
        lambda got: len(got) == 1,
    )
    assert [p["Name"] for p in owned_path_read] == [own_name], (
        "the owned path read must return exactly the owned parameter, got "
        f"{[p['Name'] for p in owned_path_read]}"
    )

    # An unpublished name inside the public namespace is a miss, not a 200 with junk.
    missing = _error(
        lambda: ssm.get_parameter(
            Name="/aws/service/ami-amazon-linux-latest/sim2real-behav-no-such-ami"
        )
    )
    assert missing == ("ParameterNotFound", ""), (
        "an unpublished name under the public namespace must be refused with "
        f"ParameterNotFound, got {missing!r}"
    )
    # An empty sub-path UNDER A PUBLISHED NAMESPACE is an empty list, not an error.
    empty = ssm.get_parameters_by_path(
        Path=_PUBLIC_PATH + "/sim2real-behav-no-such-subpath", Recursive=True
    )
    assert empty["Parameters"] == [], (
        f"an unknown path beneath a published namespace must return an empty list, got "
        f"{empty['Parameters']}"
    )
    assert "NextToken" not in empty, (
        f"an empty page must not carry a NextToken, got {empty.get('NextToken')!r}"
    )
    # An unrecognised namespace under /aws/ is refused outright, naming the namespace.
    unknown_ns = "/aws/service/sim2real-behav-no-such-namespace"
    ns_code = None
    ns_msg = None
    try:
        ssm.get_parameters_by_path(Path=unknown_ns, Recursive=True)
    except ClientError as exc:
        ns_code = exc.response.get("Error", {}).get("Code")
        ns_msg = exc.response.get("Error", {}).get("Message") or ""
    assert ns_code == "AccessDeniedException", (
        f"an unrecognised namespace under /aws/ must be refused with AccessDeniedException, got "
        f"{ns_code!r}: {ns_msg!r}"
    )
    assert ns_msg == (
        f'No access to "/aws/" namespace: {unknown_ns.lstrip("/")} is not a valid namespace'
    ), f"unexpected unknown-namespace diagnostic: {ns_msg!r}"

    # A two-segment /aws/ path fails the name grammar ("can't be prefixed with aws") before
    # any namespace lookup, so it gets a different code.
    shallow_code, shallow_msg = _error(
        lambda: ssm.get_parameters_by_path(Path="/aws/sim2real-behav-no-such", Recursive=True)
    )
    assert shallow_code == "ValidationException", (
        f"a two-segment /aws/ path is refused by the name grammar, not the namespace lookup; got "
        f"{shallow_code!r}"
    )
    # AWS's text carries literal backslashes before the quotes around aws and ssm.
    assert shallow_msg == (
        "The parameter doesn't meet the parameter name requirements. The parameter name must "
        'begin with a forward slash "/". It can\'t be prefixed with \\"aws\\" or \\"ssm\\" '
        "(case-insensitive). It must use only letters, numbers, or the following symbols: . "
        "(period), - (hyphen), _ (underscore). Special characters are not allowed. All "
        'sub-paths, if specified, must use the forward slash symbol "/". Valid example: '
        "/get/parameters2-/by1./path0_."
    ), shallow_msg
    assert shallow_code != ns_code, (shallow_code, ns_code)

    # PutParameter into the reserved namespace is refused too, so the public namespace is
    # readable-but-not-writable rather than merely unowned.
    write_code = None
    write_msg = None
    reserved_write = _PUBLIC_PATH + "/sim2real-behav-must-not-exist"
    try:
        ssm.put_parameter(Name=reserved_write, Value="must-not-exist", Type="String")
    except ClientError as exc:
        write_code = exc.response.get("Error", {}).get("Code")
        write_msg = exc.response.get("Error", {}).get("Message") or ""
    assert write_code == "AccessDeniedException", (
        f"writing into the AWS public namespace must be refused with AccessDeniedException, got "
        f"{write_code!r}: {write_msg!r}"
    )
    # A third distinct diagnostic: the namespace exists, so the refusal is about the parameter
    # being restricted, not about the namespace being unrecognised.
    assert write_msg == "Cannot access/update data for the restricted parameter.", (
        f"unexpected restricted-write diagnostic: {write_msg!r}"
    )
    assert write_msg != ns_msg, (write_msg, ns_msg)
    assert _error(lambda: ssm.get_parameter(Name=reserved_write)) == ("ParameterNotFound", ""), (
        f"the refused write must not have created {reserved_write}"
    )


if __name__ == "__main__":
    from fidelity_tests_runner import main
    main(run)
