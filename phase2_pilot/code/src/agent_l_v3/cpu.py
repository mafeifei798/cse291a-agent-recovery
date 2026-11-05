"""Same strict CPU tools; nested timing never changes worker contracts."""
from agent_l_v1.cpu import ActualCPU


class TimedCPU(ActualCPU):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.timing = None

    def _run(self, spec):
        name = 'numeric_worker_roundtrip' if spec['schema_version'] == 'context-cutoff-numeric-v1' else 'fit_worker_roundtrip'
        with self.timing.span(name): return super()._run(spec)

    def fit(self, *args, **kwargs):
        with self.timing.span('CPU_fit_bridge'): return super().fit(*args, **kwargs)

    def validate(self, *args, **kwargs):
        with self.timing.span('artifact_and_binding_checks'): return super().validate(*args, **kwargs)

    def admit(self, *args, **kwargs):
        with self.timing.span('CPU_readmission'): return super().admit(*args, **kwargs)
