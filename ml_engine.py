import joblib
import re
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
MODELS_DIR = BASE_DIR / "models"

svm_model = joblib.load(MODELS_DIR / "svm_model.pkl")
svm_tfidf = joblib.load(MODELS_DIR / "tfidf_vectorizer.pkl")
svm_svd = joblib.load(MODELS_DIR / "svm_svd.pkl")

rf_model = joblib.load(MODELS_DIR / "random_forest_model.pkl")
rf_tfidf = joblib.load(MODELS_DIR / "rf_tfidf.pkl")
rf_svd = joblib.load(MODELS_DIR / "rf_svd.pkl")


def clean_text(text):
    text = str(text).lower()
    text = re.sub(r"http\S+|www\S+", " URL ", text)
    text = re.sub(r"\S+@\S+", " EMAIL ", text)
    text = re.sub(r"\d+", " ", text)
    text = re.sub(r"[^a-z\s]", " ", text)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def run_ml(email_text):
    text = clean_text(email_text)

    if len(text.split()) < 5:
        return {
          "svm": 0,
            "rf": 0,
            "ml_final": 0,
            "svm_prob": 0.0,
            "rf_prob": 0.0,
            "skipped": True
        }

    svm_vec = svm_tfidf.transform([text])
    svm_vec_svd = svm_svd.transform(svm_vec)
    svm_prob = float(svm_model.predict_proba(svm_vec_svd)[0][1])
    svm_pred = 1 if svm_prob >= 0.75 else 0

    rf_vec = rf_tfidf.transform([text])
    rf_vec_svd = rf_svd.transform(rf_vec)
    rf_prob = float(rf_model.predict_proba(rf_vec_svd)[0][1])
    rf_pred = 1 if rf_prob >= 0.70 else 0

    votes = [svm_pred, rf_pred]

    if votes.count(1) > votes.count(0):
        ml_final = 1
    elif votes.count(0) > votes.count(1):
        ml_final = 0
    else:
        if max(svm_prob, rf_prob) >= 0.75:
            ml_final = 1
        else:
            ml_final = 0

    return {
        "svm": svm_pred,
        "rf": rf_pred,
        "ml_final": ml_final,
        "svm_prob": round(svm_prob, 3),
        "rf_prob": round(rf_prob, 3),
        "ml_confidence": round(max(svm_prob, rf_prob), 3),
        "skipped": False
    }