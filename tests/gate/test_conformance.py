from __future__ import annotations

from agent_gate.gate.executor import HostMediatedExecutor
from agent_gate.gate.profile import DEFAULT_CLAIMED_GRADE, build_profile, deployment_profile


def test_default_claimed_grade_is_advisory():
    assert DEFAULT_CLAIMED_GRADE == "advisory"


def test_run_conformance_against_the_gate_executor():
    profile = build_profile(executor=HostMediatedExecutor())
    assert profile.report.scenarios


def test_deployment_profile_reports_advisory_by_default():
    profile = deployment_profile()
    assert profile.claimed_grade == DEFAULT_CLAIMED_GRADE
    assert profile.reported_grade() == "advisory"
    assert profile.verified


def test_claiming_mediated_without_attestation_is_downgraded():
    profile = build_profile(executor=HostMediatedExecutor(), claimed_grade="mediated")
    assert profile.observed_grade == "advisory"
    assert profile.reported_grade() == "advisory"
    assert not profile.verified
