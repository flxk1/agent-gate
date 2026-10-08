from __future__ import annotations

from typing import Optional

from a2a_compliance.wire.conformance_kit import Profile, dev_conformance_ports, run_conformance
from a2a_compliance.wire.executor import ExecutorPort

from .executor import HostMediatedExecutor

DEFAULT_CLAIMED_GRADE = "advisory"


def build_profile(
    *, executor: Optional[ExecutorPort] = None, claimed_grade: str = DEFAULT_CLAIMED_GRADE,
    no_alternate_path_attested: bool = False, platform_boundary_attested: bool = False,
) -> Profile:
    ports = dev_conformance_ports(executor=executor or HostMediatedExecutor())
    report = run_conformance(ports)
    return Profile(
        claimed_grade=claimed_grade, report=report,
        no_alternate_path_attested=no_alternate_path_attested,
        platform_boundary_attested=platform_boundary_attested,
    )


def deployment_profile() -> Profile:
    return build_profile()
