"""
threatpipe
==========

Real-time threat detection pipeline built on top of the explainable
intrusion-detection research code base. The package wires together:

* streaming log ingestion (file tail, syslog, JSON-lines)
* event normalization into a common provenance-style schema
* multiple detection engines (rule-based, statistical, isolation forest,
  autoencoder, ensemble)
* a REST API server and CLI front-end
* a pluggable alerting system

The goal is to take the offline notebooks shipped in ``system/`` and make
them usable as an actual on-line service, while still allowing the same
explainability hooks to be plugged in afterwards.
"""

from .version import __version__

__all__ = ["__version__"]
