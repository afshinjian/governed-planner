"""governed-planner — upstream planning system for governed-runtime.

Design basis: design/GP-SPK-001-governance-kernel.md

This package currently contains only the GP-SPK-001 governance kernel feasibility
spike. No AI planning layer is authorized for implementation.

Nothing is re-exported here on purpose: the module boundaries are load-bearing
(§4 of the design), and a convenience re-export would let an importer reach the
kernel without going through the layer that validates its input.
"""

__version__ = "0.1.0"
