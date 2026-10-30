"""The Guardian: a guard for AI agents. Rules decide what an agent may do; a detector reads untrusted text first."""
from guardian.detect import Detection, HeuristicDetector, ModelDetector
from guardian.gateway import Blocked, Guardian
from guardian.policy import Decision, Policy

__version__ = "0.4.0"
