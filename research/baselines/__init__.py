"""
SecuraX Research Baselines Package
====================================
Provides four risk classification baselines for comparative evaluation:

    Baseline-CVSS      Naive severity lookup (lower bound)
    Baseline-Rule      Fixed heuristics (internet_facing + counts)
    Baseline-Priority  CVSS + asset criticality (no temporal)
    Baseline-Random    Uniform random (statistical floor)

Usage:
    from research.baselines import get_baseline

    baseline = get_baseline("cvss")
    risk = baseline.classify(scan_input, **kwargs)
    print(baseline.metadata())
"""

from typing import Protocol


class BaselineProtocol(Protocol):
    """Interface that all baselines must implement."""

    NAME: str
    VERSION: str
    DESCRIPTION: str

    def classify(self, scan_input: dict, **kwargs) -> str: ...
    def metadata(self) -> dict: ...


def get_baseline(name: str):
    """
    Return a baseline module by name.

    Args:
        name: One of {cvss, rule, random, priority}

    Returns:
        Baseline module with .classify() and .metadata() functions.

    Raises:
        ValueError: If the baseline name is not recognised.
    """
    name = name.lower().strip()
    if name == "cvss":
        from research.baselines import baseline_cvss
        return baseline_cvss
    elif name == "rule":
        from research.baselines import baseline_rule
        return baseline_rule
    elif name == "random":
        from research.baselines import baseline_random
        return baseline_random
    elif name == "priority":
        from research.baselines import baseline_priority
        return baseline_priority
    else:
        raise ValueError(
            f"Unknown baseline '{name}'. "
            f"Available: cvss, rule, random, priority"
        )


ALL_BASELINES = ["cvss", "rule", "priority", "random"]
