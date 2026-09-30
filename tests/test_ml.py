import pytest

from phishguard import analyze_url
from phishguard.analyzer import ML_WEIGHTS, SUSPICIOUS_THRESHOLD
from phishguard.ml import N_BUCKETS, N_FEATURES, DomainModel, domain_features, load_model


def test_features_are_deterministic_and_in_range():
    first = domain_features("paypal-login", "com")
    assert first == domain_features("paypal-login", "com")
    assert all(0 <= index < N_FEATURES for index in first)
    assert first[N_BUCKETS + 6] == 1.0  # brand feature


def test_brand_feature_off_for_official_domain():
    assert N_BUCKETS + 6 not in domain_features("paypal", "com")


def test_model_from_dict_rejects_wrong_size():
    with pytest.raises(ValueError):
        DomainModel([0.0] * 3, 0.0, {})


def test_predict_proba_uses_weights():
    features = domain_features("abc", "com")
    weights = {str(i): 1.0 for i in features}
    model = DomainModel.from_dict({"weights": weights, "bias": -100.0})
    assert model.predict_proba("abc", "com") < 0.01
    model = DomainModel.from_dict({"weights": weights, "bias": 100.0})
    assert model.predict_proba("abc", "com") > 0.99


def test_ml_alone_cannot_reach_suspicious():
    assert max(weight for _, weight in ML_WEIGHTS) < SUSPICIOUS_THRESHOLD


model = load_model()


@pytest.mark.skipif(model is None, reason="modelo no entrenado")
def test_bundled_model_metadata():
    assert model.metadata["test_metrics"]["roc_auc"] > 0.8


@pytest.mark.skipif(model is None, reason="modelo no entrenado")
def test_report_includes_ml_probability():
    report = analyze_url("https://some-random-shop.com/")
    assert 0.0 <= report.ml_probability <= 1.0
    assert analyze_url("https://www.paypal.com/").ml_probability is None  # official domain
    assert analyze_url("http://10.0.0.1/").ml_probability is None
