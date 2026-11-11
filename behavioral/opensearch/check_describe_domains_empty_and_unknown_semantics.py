"""describe-domains-empty-and-unknown-semantics."""
from __future__ import annotations

from behavioral_harness import tags
CHECK = "describe-domains-empty-and-unknown-semantics"
GROUP = 'domain'
SERVICES = ['opensearch']

def _missing_domain_name(ctx) -> str:
    """A syntactically valid domain name that is guaranteed not to exist."""
    return ctx.unique_name('sim2real-behav-os-missing-')[:28].rstrip('-')

@tags("axis:happy-path", "cap:c1", "concern:representation", "plane:control")
def run(ctx) -> None:
    """DescribeDomains with an empty DomainNames list, or only an unknown name, returns an empty
    DomainStatusList instead of an error.
    """
    os = ctx.client('opensearch')
    resp = os.describe_domains(DomainNames=[])
    empty_status_list = resp['DomainStatusList']
    assert empty_status_list == [], f"empty DomainNames must yield an empty DomainStatusList, got {empty_status_list}"
    only_missing = os.describe_domains(DomainNames=[_missing_domain_name(ctx)])
    missing_status_list = only_missing['DomainStatusList']
    assert missing_status_list == [], f"DescribeDomains must not fabricate a status for an unknown domain, got {missing_status_list}"
if __name__ == '__main__':
    from fidelity_tests_runner import main
    main(run)
