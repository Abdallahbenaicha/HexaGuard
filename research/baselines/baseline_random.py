"""
SecuraX Risk Engine Baseline — Random
=======================================
Assigns random risk levels from a uniform distribution.

This is NOT a serious classifier. It serves as a **statistical lower bound**:
any real classifier (CVSS, Rule, or SecuraX) must outperform random chance.

If SecuraX does not significantly outperform this baseline, something is
fundamentally wrong with the experiment or the engine.

Research use:
    - Cited in all SecuraX benchmark results as 'Baseline-Random'.
    - Expected to achieve macro-F1 ≈ 0.20 on a 5-class balanced dataset.
    - Used only for sanity checking, not scientific comparison.

References:
    [ML-EVAL] Sokolova & Lapalme. "A systematic analysis of performance measures
              for classification tasks." Information Processing & Management,
              45(4):427-437, 2009. https://doi.org/10.1016/j.ipm.2009.03.002

Baseline identifier: baseline_random
Version: 1.0.0

WARNING: Results will vary across runs due to randomness.
         Use a fixed seed (--seed N) for reproducible experiments.
"""

import random

NAME = "Baseline-Random"
VERSION = "1.0.0"
DESCRIPTION = (
    "Random baseline: assigns uniformly random risk levels. "
    "Serves as a statistical lower bound — expected macro-F1 ≈ 0.20."
)

_RISK_LEVELS = ["minimal", "low", "medium", "high", "critical"]
_rng = random.Random()  # Thread-local RNG for reproducibility


def set_seed(seed: int) -> None:
    """Set the random seed for reproducible experiments."""
    _rng.seed(seed)


def classify(scan_input: dict, **_kwargs) -> str:
    """
    Classify risk level by random uniform sampling.

    Args:
        scan_input: Ignored. Present for interface compatibility.
        **_kwargs:  Ignored. Present for interface compatibility.

    Returns:
        A uniformly random risk level from {minimal, low, medium, high, critical}.
    """
    return _rng.choice(_RISK_LEVELS)


def metadata() -> dict:
    """Return baseline metadata for experiment results."""
    return {
        "name": NAME,
        "version": VERSION,
        "description": DESCRIPTION,
        "contextual_factors": [],
        "references": [
            "https://doi.org/10.1016/j.ipm.2009.03.002",
        ],
        "warning": "Results are non-deterministic without a fixed seed.",
    }
