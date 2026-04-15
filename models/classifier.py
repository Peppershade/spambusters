"""
PyTorch-based spam classifier for Spambuster.
Supports Dutch and English emails.
Per-user model support for multi-tenant SaaS.
"""
import logging
import os
import re
import pickle
from typing import Tuple, List, Optional, Dict

logger = logging.getLogger(__name__)

import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
from sklearn.feature_extraction.text import TfidfVectorizer

from config import Config
import unicodedata

# Call-to-action patterns (English + Dutch) - strong spam indicators
CTA_PATTERNS = [
    # English
    re.compile(r'\bclick\s+here\b', re.IGNORECASE),
    re.compile(r'\bact\s+now\b', re.IGNORECASE),
    re.compile(r'\bbuy\s+now\b', re.IGNORECASE),
    re.compile(r'\bsign\s+up\b', re.IGNORECASE),
    re.compile(r'\bregister\s+now\b', re.IGNORECASE),
    re.compile(r'\bcall\s+now\b', re.IGNORECASE),
    re.compile(r'\border\s+now\b', re.IGNORECASE),
    re.compile(r'\bdownload\s+now\b', re.IGNORECASE),
    re.compile(r'\bclaim\s+your\b', re.IGNORECASE),
    re.compile(r"\bdon'?t\s+miss\b", re.IGNORECASE),
    re.compile(r'\blimited\s+time\b', re.IGNORECASE),
    re.compile(r'\brespond\s+immediately\b', re.IGNORECASE),
    re.compile(r'\bopen\s+the\s+attachment\b', re.IGNORECASE),
    re.compile(r'\bconfirm\s+your\s+identity\b', re.IGNORECASE),
    re.compile(r'\bverify\s+now\b', re.IGNORECASE),
    re.compile(r'\bupdate\s+your\s+payment\b', re.IGNORECASE),
    # Dutch
    re.compile(r'\bklik\s+hier\b', re.IGNORECASE),
    re.compile(r'\bnu\s+handelen\b', re.IGNORECASE),
    re.compile(r'\bkoop\s+nu\b', re.IGNORECASE),
    re.compile(r'\bschrijf\s+je\s+in\b', re.IGNORECASE),
    re.compile(r'\bregistreer\s+nu\b', re.IGNORECASE),
    re.compile(r'\bbel\s+nu\b', re.IGNORECASE),
    re.compile(r'\bbestel\s+nu\b', re.IGNORECASE),
    re.compile(r'\bdownload\s+nu\b', re.IGNORECASE),
    re.compile(r'\bclaim\s+je\b', re.IGNORECASE),
    re.compile(r'\bmis\s+het\s+niet\b', re.IGNORECASE),
    re.compile(r'\breageer\s+direct\b', re.IGNORECASE),
    re.compile(r'\bopen\s+de\s+bijlage\b', re.IGNORECASE),
    re.compile(r'\bbevestig\s+je\s+identiteit\b', re.IGNORECASE),
    re.compile(r'\bverifieer\s+nu\b', re.IGNORECASE),
    re.compile(r'\bwerk\s+je\s+betaling\s+bij\b', re.IGNORECASE),
]


# Homoglyph mapping - Unicode lookalikes to ASCII
HOMOGLYPHS = {
    # Lisu script
    'ꓮ': 'A', 'ꓐ': 'B', 'ꓚ': 'C', 'ꓓ': 'D', 'ꓰ': 'E', 'ꓝ': 'F', 'ꓖ': 'G',
    'ꓧ': 'H', 'ꓲ': 'I', 'ꓙ': 'J', 'ꓗ': 'K', 'ꓡ': 'L', 'ꓟ': 'M', 'ꓠ': 'N',
    'ꓳ': 'O', 'ꓑ': 'P', 'ꓤ': 'Q', 'ꓣ': 'R', 'ꓢ': 'S', 'ꓔ': 'T', 'ꓴ': 'U',
    'ꓦ': 'V', 'ꓪ': 'W', 'ꓫ': 'X', 'ꓬ': 'Y', 'ꓜ': 'Z',
    # Cyrillic lookalikes
    'а': 'a', 'е': 'e', 'о': 'o', 'р': 'p', 'с': 'c', 'у': 'y', 'х': 'x',
    'А': 'A', 'В': 'B', 'С': 'C', 'Е': 'E', 'Н': 'H', 'К': 'K', 'М': 'M',
    'О': 'O', 'Р': 'P', 'Т': 'T', 'Х': 'X', 'У': 'Y',
    # Greek lookalikes
    'Α': 'A', 'Β': 'B', 'Ε': 'E', 'Η': 'H', 'Ι': 'I', 'Κ': 'K', 'Μ': 'M',
    'Ν': 'N', 'Ο': 'O', 'Ρ': 'P', 'Τ': 'T', 'Χ': 'X', 'Υ': 'Y', 'Ζ': 'Z',
    'α': 'a', 'ο': 'o', 'ν': 'v', 'ρ': 'p', 'τ': 't', 'υ': 'u',
    # Common substitutions
    '０': '0', '１': '1', '２': '2', '３': '3', '４': '4',
    '５': '5', '６': '6', '７': '7', '８': '8', '９': '9',
    'ⅰ': 'i', 'ⅱ': 'ii', 'ⅲ': 'iii', 'ⅳ': 'iv', 'ⅴ': 'v',
    '!': '!', '?': '?',  # Fullwidth
    'ℓ': 'l', 'ℐ': 'I', 'ℑ': 'I', 'ℒ': 'L', 'ℳ': 'M', 'ℛ': 'R', 'ℬ': 'B',
    'ⓐ': 'a', 'ⓑ': 'b', 'ⓒ': 'c', 'ⓓ': 'd', 'ⓔ': 'e', 'ⓕ': 'f', 'ⓖ': 'g',
    'ⓗ': 'h', 'ⓘ': 'i', 'ⓙ': 'j', 'ⓚ': 'k', 'ⓛ': 'l', 'ⓜ': 'm', 'ⓝ': 'n',
    'ⓞ': 'o', 'ⓟ': 'p', 'ⓠ': 'q', 'ⓡ': 'r', 'ⓢ': 's', 'ⓣ': 't', 'ⓤ': 'u',
    'ⓥ': 'v', 'ⓦ': 'w', 'ⓧ': 'x', 'ⓨ': 'y', 'ⓩ': 'z',
}

# Suspicious Unicode script ranges (not typically in legitimate Dutch/English emails)
SUSPICIOUS_SCRIPTS = {
    'LISU', 'CYRILLIC', 'GREEK', 'ARMENIAN', 'GEORGIAN', 'CHEROKEE',
    'CANADIAN_ABORIGINAL', 'OGHAM', 'RUNIC', 'COPTIC', 'GLAGOLITIC'
}


def normalize_homoglyphs(text: str) -> str:
    """Convert Unicode lookalike characters to ASCII equivalents."""
    result = []
    for char in text:
        if char in HOMOGLYPHS:
            result.append(HOMOGLYPHS[char])
        else:
            result.append(char)
    return ''.join(result)


def detect_mixed_scripts(text: str) -> dict:
    """
    Detect suspicious Unicode scripts in text.
    Returns dict with script counts and suspicion indicators.
    """
    script_counts = {}
    suspicious_chars = []

    for char in text:
        if char.isalpha():
            try:
                script = unicodedata.name(char, '').split()[0]
                script_counts[script] = script_counts.get(script, 0) + 1

                # Check if it's a suspicious script
                for sus_script in SUSPICIOUS_SCRIPTS:
                    if sus_script in unicodedata.name(char, '').upper():
                        suspicious_chars.append(char)
                        break
            except (ValueError, IndexError):
                pass

    return {
        'script_counts': script_counts,
        'num_scripts': len(script_counts),
        'suspicious_chars': suspicious_chars,
        'has_suspicious_scripts': len(suspicious_chars) > 0,
        'suspicious_char_count': len(suspicious_chars)
    }


# Device configuration
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")


class SpamClassifierNet(nn.Module):
    """Neural network for spam classification."""

    def __init__(self, input_size: int, hidden_size: int = 256):
        super(SpamClassifierNet, self).__init__()
        self.network = nn.Sequential(
            nn.Linear(input_size, hidden_size),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_size, hidden_size // 2),
            nn.ReLU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size // 2, 1),
            nn.Sigmoid()
        )

    def forward(self, x):
        return self.network(x)


class SpamClassifier:
    """
    Spam classifier using TF-IDF features and a neural network.
    Supports Dutch and English text.
    Per-user model support for multi-tenant SaaS.
    """

    # Default spam indicators (Dutch and English) - used as fallback and for initialization
    DEFAULT_SPAM_KEYWORDS = {
        # English
        "winner", "congratulations", "lottery", "prize", "urgent", "act now",
        "limited time", "free", "click here", "unsubscribe", "buy now",
        "million dollars", "inheritance", "bank transfer", "western union",
        "nigerian", "prince", "account suspended", "verify your account",
        "password expired", "security alert", "unusual activity", "account blocked",
        "account locked", "suspended", "blocked",
        # Dutch
        "winnaar", "gefeliciteerd", "loterij", "prijs", "dringend", "nu handelen",
        "beperkte tijd", "gratis", "klik hier", "afmelden", "koop nu",
        "miljoen euro", "erfenis", "bankoverschrijving", "rekening opgeschort",
        "verifieer uw account", "wachtwoord verlopen", "beveiligingswaarschuwing",
        "ongebruikelijke activiteit", "betaling mislukt", "factuur", "bitcoin", "herinnering", "actie",
        "abonnement", "geblokkeerd", "vergrendeld", "opgeschort", "uw account"
    }

    def __init__(self, user_id: int):
        """
        Initialize classifier for a specific user.

        Args:
            user_id: User ID for per-user model storage
        """
        self.user_id = user_id
        self.model: Optional[SpamClassifierNet] = None
        self.vectorizer: Optional[TfidfVectorizer] = None
        self.is_trained = False
        self._init_keywords()
        self._load_if_exists()

    @property
    def model_dir(self) -> str:
        """Get user-specific model directory."""
        return os.path.join(Config.MODELS_DIR, str(self.user_id))

    @property
    def model_path(self) -> str:
        """Get user-specific model path."""
        return os.path.join(self.model_dir, "spam_model.pt")

    @property
    def vectorizer_path(self) -> str:
        """Get user-specific vectorizer path."""
        return os.path.join(self.model_dir, "vectorizer.pkl")

    def _init_keywords(self):
        """Initialize spam keywords from database, seeding defaults if empty."""
        from database import init_default_spam_keywords
        init_default_spam_keywords(self.user_id, self.DEFAULT_SPAM_KEYWORDS)

    def detect_cta(self, text: str) -> dict:
        """Detect call-to-action phrases in text. Returns count and matched CTAs."""
        matched = []
        for pattern in CTA_PATTERNS:
            match = pattern.search(text)
            if match:
                matched.append(match.group())
        return {"count": len(matched), "matched": matched}

    @property
    def SPAM_KEYWORDS(self) -> set:
        """Get spam keywords from database for this user."""
        from database import get_spam_keywords
        keywords = get_spam_keywords(self.user_id)
        return set(keywords) if keywords else self.DEFAULT_SPAM_KEYWORDS

    def _load_if_exists(self):
        """Load existing model and vectorizer if available."""
        if os.path.exists(self.model_path) and os.path.exists(self.vectorizer_path):
            try:
                # Load vectorizer
                with open(self.vectorizer_path, "rb") as f:
                    self.vectorizer = pickle.load(f)

                # Load model
                input_size = len(self.vectorizer.get_feature_names_out())
                self.model = SpamClassifierNet(input_size).to(DEVICE)
                self.model.load_state_dict(torch.load(self.model_path, map_location=DEVICE, weights_only=True))
                self.model.eval()
                self.is_trained = True
                logger.info("Loaded existing model for user %s with %d features", self.user_id, input_size)
            except Exception as e:
                logger.error("Error loading model for user %s: %s", self.user_id, e)
                self.model = None
                self.vectorizer = None
                self.is_trained = False

    def preprocess_text(self, text: str) -> str:
        """Clean and preprocess email text."""
        # Convert to lowercase
        text = text.lower()

        # Remove URLs but keep a marker
        text = re.sub(r'https?://\S+', ' URL_LINK ', text)

        # Remove email addresses but keep a marker
        text = re.sub(r'\S+@\S+', ' EMAIL_ADDR ', text)

        # Remove HTML tags
        text = re.sub(r'<[^>]+>', ' ', text)

        # Remove special characters but keep letters, numbers, and spaces
        text = re.sub(r'[^a-zA-Z0-9\s]', ' ', text)

        # Remove extra whitespace
        text = ' '.join(text.split())

        return text

    def extract_features(self, text: str) -> dict:
        """Extract additional features from email text."""
        # Normalize homoglyphs for keyword detection
        normalized_text = normalize_homoglyphs(text)

        # Detect suspicious scripts
        script_info = detect_mixed_scripts(text)

        features = {
            "url_count": len(re.findall(r'https?://\S+', text)),
            "email_count": len(re.findall(r'\S+@\S+', text)),
            "uppercase_ratio": sum(1 for c in text if c.isupper()) / max(len(text), 1),
            "exclamation_count": text.count("!") + text.count("!"),  # Include fullwidth
            "question_count": text.count("?") + text.count("?"),  # Include fullwidth
            # Check keywords against BOTH original and normalized text
            "spam_keyword_count": sum(1 for kw in self.SPAM_KEYWORDS if kw in text.lower() or kw in normalized_text.lower()),
            # Unicode obfuscation detection
            "has_suspicious_scripts": script_info['has_suspicious_scripts'],
            "suspicious_char_count": script_info['suspicious_char_count'],
            "num_scripts": script_info['num_scripts'],
            # Call-to-action detection
            "cta_count": self.detect_cta(text)["count"],
        }
        return features

    def _get_weights(self) -> dict:
        """Get configurable scoring weights from database for this user."""
        from database import get_user_setting
        return {
            "urls": float(get_user_setting(self.user_id, "weight_urls", "0.3")),
            "model": float(get_user_setting(self.user_id, "weight_model", "0.7")),
            "keywords": float(get_user_setting(self.user_id, "weight_keywords", "0.3")),
        }

    def heuristic_score(self, text: str) -> float:
        """
        Calculate a heuristic spam score based on known patterns.
        Returns a value between 0 and 1.
        """
        features = self.extract_features(text)
        weights = self._get_weights()
        score = 0.0

        # URL heavy emails are suspicious (scaled by weight_urls)
        url_weight = weights["urls"] / 0.3  # normalize so default weight=1.0
        if features["url_count"] > 3:
            score += 0.2 * url_weight
        elif features["url_count"] > 1:
            score += 0.1 * url_weight

        # Spam keywords - aggressive scoring (scaled by weight_keywords)
        kw_weight = weights["keywords"] / 0.3
        if features["spam_keyword_count"] >= 1:
            score += min(0.7, features["spam_keyword_count"] * 0.25) * kw_weight

        # Excessive uppercase
        if features["uppercase_ratio"] > 0.3:
            score += 0.15
        elif features["uppercase_ratio"] > 0.15:
            score += 0.05

        # Exclamation marks - suspicious, especially multiple
        if features["exclamation_count"] >= 2:
            score += min(0.2, features["exclamation_count"] * 0.08)
        elif features["exclamation_count"] >= 1:
            score += 0.03

        # Question marks can also be spammy
        if features["question_count"] > 3:
            score += 0.05

        # Call-to-action detection
        cta_count = features["cta_count"]
        if cta_count >= 2:
            score += 0.25
        elif cta_count == 1:
            score += 0.15

        # Unicode obfuscation - very strong spam signal
        if features["has_suspicious_scripts"]:
            score += min(0.5, features["suspicious_char_count"] * 0.05)

        # Multiple different scripts mixed together is suspicious
        if features["num_scripts"] > 2:
            score += 0.1

        # Bonus for multiple indicators combined (compounds suspicion)
        indicators = sum([
            features["spam_keyword_count"] >= 2,
            features["exclamation_count"] >= 2,
            features["url_count"] >= 2,
            features["uppercase_ratio"] > 0.2,
            features["has_suspicious_scripts"],
            cta_count >= 1
        ])
        if indicators >= 2:
            score += 0.15

        return min(score, 1.0)

    def train(self, texts: List[str], labels: List[int], epochs: int = 10) -> dict:
        """
        Train the spam classifier.

        Args:
            texts: List of email contents
            labels: List of labels (1 for spam, 0 for ham)
            epochs: Number of training epochs

        Returns:
            Training statistics
        """
        if len(texts) < 5:
            return {"error": "Need at least 5 samples to train", "success": False}

        # Preprocess texts
        processed_texts = [self.preprocess_text(t) for t in texts]

        # Create/fit vectorizer
        self.vectorizer = TfidfVectorizer(
            max_features=5000,
            ngram_range=(1, 2),
            min_df=1,
            max_df=0.95
        )
        X = self.vectorizer.fit_transform(processed_texts).toarray()

        # Convert to tensors
        X_tensor = torch.tensor(X, dtype=torch.float32).to(DEVICE)
        y_tensor = torch.tensor(labels, dtype=torch.float32).unsqueeze(1).to(DEVICE)

        # Create dataset and loader
        dataset = TensorDataset(X_tensor, y_tensor)
        dataloader = DataLoader(dataset, batch_size=32, shuffle=True)

        # Initialize model
        input_size = X.shape[1]
        self.model = SpamClassifierNet(input_size).to(DEVICE)

        # Training setup
        criterion = nn.BCELoss()
        optimizer = optim.Adam(self.model.parameters(), lr=0.001)

        # Training loop
        self.model.train()
        history = {"losses": [], "accuracy": []}

        for epoch in range(epochs):
            total_loss = 0
            correct = 0
            total = 0

            for inputs, targets in dataloader:
                optimizer.zero_grad()
                outputs = self.model(inputs)
                loss = criterion(outputs, targets)
                loss.backward()
                optimizer.step()

                total_loss += loss.item()
                predicted = (outputs >= 0.5).float()
                correct += (predicted == targets).sum().item()
                total += targets.size(0)

            avg_loss = total_loss / len(dataloader)
            accuracy = correct / total
            history["losses"].append(avg_loss)
            history["accuracy"].append(accuracy)
            logger.info("Epoch %d/%d, Loss: %.4f, Accuracy: %.4f", epoch + 1, epochs, avg_loss, accuracy)

        # Save model and vectorizer
        self._save()
        self.is_trained = True

        return {
            "success": True,
            "epochs": epochs,
            "final_loss": history["losses"][-1],
            "final_accuracy": history["accuracy"][-1],
            "samples": len(texts),
            "features": input_size
        }

    def predict(self, text: str) -> Tuple[float, bool]:
        """
        Predict if an email is spam.

        Args:
            text: Email content

        Returns:
            Tuple of (spam_score, is_spam)
        """
        # If model not trained, use heuristics only
        if not self.is_trained or self.model is None or self.vectorizer is None:
            heuristic = self.heuristic_score(text)
            return heuristic, heuristic >= Config.SPAM_THRESHOLD

        # Preprocess and vectorize
        processed = self.preprocess_text(text)
        X = self.vectorizer.transform([processed]).toarray()
        X_tensor = torch.tensor(X, dtype=torch.float32).to(DEVICE)

        # Predict
        self.model.eval()
        with torch.no_grad():
            output = self.model(X_tensor)
            model_score = output.item()

        # Combine with heuristics
        heuristic = self.heuristic_score(text)
        weights = self._get_weights()
        model_weight = weights["model"]
        heuristic_weight = 1.0 - model_weight

        # Use weighted average, but allow strong heuristic signals to boost score
        if heuristic >= 0.5:
            # Strong heuristic signal - use 50/50 weighting
            combined_score = 0.5 * model_score + 0.5 * heuristic
        else:
            # Normal weighting - configurable model vs heuristic balance
            combined_score = model_weight * model_score + heuristic_weight * heuristic

        return combined_score, combined_score >= Config.SPAM_THRESHOLD

    def explain_prediction(self, text: str) -> dict:
        """
        Explain why an email was classified as spam or safe.

        Returns:
            Dictionary with reasons and contributing factors
        """
        reasons = []
        features = self.extract_features(text)
        text_lower = text.lower()
        normalized_text = normalize_homoglyphs(text).lower()

        # Check for Unicode obfuscation FIRST - this is a major red flag
        if features["has_suspicious_scripts"]:
            script_info = detect_mixed_scripts(text)
            reasons.append({
                "type": "unicode_obfuscation",
                "severity": "critical",
                "detail": f"Suspicious Unicode characters detected ({features['suspicious_char_count']} chars) - possible homoglyph attack"
            })

        # Check for spam keywords found (in both original and normalized text)
        found_keywords = [kw for kw in self.SPAM_KEYWORDS if kw in text_lower]
        found_in_normalized = [kw for kw in self.SPAM_KEYWORDS if kw in normalized_text and kw not in text_lower]

        if found_keywords:
            reasons.append({
                "type": "keywords",
                "severity": "high" if len(found_keywords) > 2 else "medium",
                "detail": f"Spam keywords detected: {', '.join(found_keywords[:5])}"
            })

        if found_in_normalized:
            reasons.append({
                "type": "obfuscated_keywords",
                "severity": "critical",
                "detail": f"Hidden spam keywords (Unicode obfuscated): {', '.join(found_in_normalized[:5])}"
            })

        # URL analysis
        if features["url_count"] > 3:
            reasons.append({
                "type": "urls",
                "severity": "medium",
                "detail": f"Contains {features['url_count']} URLs (suspicious)"
            })

        # Uppercase ratio
        if features["uppercase_ratio"] > 0.3:
            reasons.append({
                "type": "formatting",
                "severity": "low",
                "detail": f"High uppercase ratio ({features['uppercase_ratio']:.0%})"
            })

        # Exclamation marks
        if features["exclamation_count"] > 5:
            reasons.append({
                "type": "formatting",
                "severity": "low",
                "detail": f"Excessive exclamation marks ({features['exclamation_count']})"
            })

        # Call-to-action detection
        cta_info = self.detect_cta(text)
        if cta_info["count"] > 0:
            severity = "high" if cta_info["count"] >= 2 else "medium"
            reasons.append({
                "type": "call_to_action",
                "severity": severity,
                "detail": f"Call-to-action phrases detected ({cta_info['count']}): {', '.join(cta_info['matched'][:5])}"
            })

        # Model contribution
        if self.is_trained:
            reasons.append({
                "type": "model",
                "severity": "info",
                "detail": "ML model pattern matching"
            })

        # If no reasons found for spam, explain why it's safe
        if not reasons:
            reasons.append({
                "type": "clean",
                "severity": "safe",
                "detail": "No suspicious patterns detected"
            })

        return {
            "reasons": reasons,
            "features": features,
            "keywords_found": found_keywords[:10],
            "obfuscated_keywords_found": found_in_normalized[:10]
        }

    def predict_batch(self, texts: List[str]) -> List[Tuple[float, bool]]:
        """Predict spam scores for multiple emails."""
        return [self.predict(text) for text in texts]

    def _save(self):
        """Save model and vectorizer to disk for this user."""
        # Ensure user model directory exists
        os.makedirs(self.model_dir, exist_ok=True)

        if self.model is not None:
            torch.save(self.model.state_dict(), self.model_path)
        if self.vectorizer is not None:
            with open(self.vectorizer_path, "wb") as f:
                pickle.dump(self.vectorizer, f)
        logger.info("Model saved to %s for user %s", self.model_path, self.user_id)


# Per-user classifier instances cache
_classifier_instances: Dict[int, SpamClassifier] = {}


def get_classifier(user_id: int) -> SpamClassifier:
    """
    Get the classifier instance for a specific user.

    Args:
        user_id: User ID

    Returns:
        SpamClassifier instance for the user
    """
    global _classifier_instances
    if user_id not in _classifier_instances:
        _classifier_instances[user_id] = SpamClassifier(user_id)
    return _classifier_instances[user_id]


def clear_classifier_cache(user_id: int = None):
    """
    Clear cached classifier instances.

    Args:
        user_id: Specific user to clear, or None for all users
    """
    global _classifier_instances
    if user_id is not None:
        _classifier_instances.pop(user_id, None)
    else:
        _classifier_instances.clear()
