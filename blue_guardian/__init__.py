"""Blue Guardian: a guard for AI agents. Rules decide what an agent may do; a detector reads untrusted text first."""
from blue_guardian.detect import Detection, HeuristicDetector, ModelDetector
from blue_guardian.gateway import Blocked, Guardian
from blue_guardian.policy import Decision, Policy

__version__ = "0.4.0"
