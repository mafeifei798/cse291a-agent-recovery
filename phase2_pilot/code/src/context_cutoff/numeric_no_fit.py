"""Fail closed on fitting inside the independent, prediction-only checker.

This is an API guard for the fixed, pinned sklearn worker, not a sandbox for
arbitrary pickle/code. It is never installed in a training worker.
"""
from contextlib import contextmanager


class NumericFitForbidden(RuntimeError):
    code = 'NUMERIC_FIT_FORBIDDEN'


def sklearn_fit_classes():
    from sklearn.pipeline import Pipeline
    from sklearn.compose import ColumnTransformer
    from sklearn.impute import SimpleImputer
    from sklearn.preprocessing import StandardScaler, OneHotEncoder
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.linear_model import LogisticRegression
    return (Pipeline, ColumnTransformer, SimpleImputer, StandardScaler,
            OneHotEncoder, RandomForestClassifier, LogisticRegression)


@contextmanager
def forbid_fitting(classes=None):
    classes = sklearn_fit_classes() if classes is None else classes
    evidence = dict(installed=True, policy='fixed-sklearn-api-no-fit-v1',
                    protected_methods=[], rejected_calls=[], model_fits=0)
    originals = []
    try:
        for cls in classes:
            for name in ('fit', 'fit_transform', 'fit_predict', 'partial_fit'):
                if not hasattr(cls, name):
                    continue
                own = name in cls.__dict__
                # Preserve the raw descriptor, not getattr's bound wrapper.
                # sklearn's available_if APIs must retain their descriptors.
                original = cls.__dict__[name] if own else None
                label = cls.__module__ + '.' + cls.__name__ + '.' + name
                def denied(*args, _label=label, **kwargs):
                    evidence['rejected_calls'].append(_label)
                    raise NumericFitForbidden('NUMERIC_FIT_FORBIDDEN:' + _label)
                originals.append((cls, name, own, original))
                setattr(cls, name, denied)
                evidence['protected_methods'].append(label)
        yield evidence
    finally:
        for cls, name, own, original in reversed(originals):
            if own:
                setattr(cls, name, original)
            else:
                delattr(cls, name)


def probe_no_fit_api(classes=None):
    """No-data calls to blocked APIs; no estimator or model is instantiated.

    With no self/data supplied an unguarded API cannot train either. Only our
    specific denial, before the original body, counts as an accepted probe.
    """
    classes = sklearn_fit_classes() if classes is None else classes
    with forbid_fitting(classes) as evidence:
        blocked = 0
        for cls in classes:
            for name in ('fit','fit_transform','fit_predict','partial_fit'):
                if not hasattr(cls,name):continue
                try:getattr(cls,name)()
                except NumericFitForbidden:blocked += 1
                else:raise RuntimeError('NUMERIC_FIT_PROBE_NOT_BLOCKED')
        passed = blocked == len(evidence['protected_methods']) > 0
    return dict(passed=passed,blocked_apis=blocked,model_fits=0,model_loads=0,
                model_predictions=0,original_api_bodies_called=0,
                protected_methods=evidence['protected_methods'])
