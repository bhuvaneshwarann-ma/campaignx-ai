import numpy as np
from typing import List, Dict, Any, Tuple
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
from backend.app.schemas.scam_dna import ScamDNASchema


def jaccard_similarity(list_a: List[str], list_b: List[str]) -> float:
    set_a = set(str(x).lower().strip() for x in list_a if x)
    set_b = set(str(x).lower().strip() for x in list_b if x)
    if not set_a or not set_b:
        return 0.0
    return len(set_a.intersection(set_b)) / len(set_a.union(set_b))


class MLCandidateGenerator:
    """
    Stage 1: Generates candidate relationships and computes raw ML relationship probability
    based on multi-modal behavioral similarity, TF-IDF text embeddings, tactic overlap,
    and infrastructure co-occurrence.
    """

    def __init__(self):
        self.vectorizer = TfidfVectorizer(ngram_range=(1, 2), max_features=500)

    def compute_candidate_probability(
        self,
        dna_a: ScamDNASchema,
        dna_b: ScamDNASchema,
        text_a: str,
        text_b: str
    ) -> Tuple[float, Dict[str, float]]:
        """
        Computes ML candidate relationship probability (0.0 to 1.0) and feature breakdown.
        """
        # 1. Text Semantic Similarity (TF-IDF Cosine)
        try:
            tfidf_matrix = self.vectorizer.fit_transform([text_a, text_b])
            text_sim = float(cosine_similarity(tfidf_matrix[0:1], tfidf_matrix[1:2])[0][0])
        except Exception:
            text_sim = 0.0

        # 2. Tactic overlap (Jaccard)
        tactic_sim = jaccard_similarity(
            dna_a.social_engineering_tactics,
            dna_b.social_engineering_tactics
        )

        # 3. Behavioral trait match (Urgency, Fear, Authority, Impersonation)
        impersonation_match = 1.0 if (
            dna_a.impersonation_target == dna_b.impersonation_target and
            dna_a.impersonation_target not in ("none", "other")
        ) else 0.0

        behavioral_distance = (
            abs(dna_a.urgency - dna_b.urgency) +
            abs(dna_a.fear - dna_b.fear) +
            abs(dna_a.authority_pressure - dna_b.authority_pressure)
        ) / 3.0
        behavioral_sim = max(0.0, 1.0 - behavioral_distance)

        # 4. Infrastructure overlap
        infra_a = dna_a.phone_numbers + dna_a.upi_ids + dna_a.domains + dna_a.urls
        infra_b = dna_b.phone_numbers + dna_b.upi_ids + dna_b.domains + dna_b.urls
        infra_sim = jaccard_similarity(infra_a, infra_b)

        # Stage 1 weighted candidate probability
        weights = {
            "infrastructure": 0.40,
            "impersonation": 0.25,
            "tactics": 0.15,
            "text": 0.10,
            "behavior": 0.10
        }

        probability = (
            (infra_sim * weights["infrastructure"]) +
            (impersonation_match * weights["impersonation"]) +
            (tactic_sim * weights["tactics"]) +
            (text_sim * weights["text"]) +
            (behavioral_sim * weights["behavior"])
        )

        factors = {
            "infrastructure_overlap": round(infra_sim, 3),
            "impersonation_match": round(impersonation_match, 3),
            "tactic_similarity": round(tactic_sim, 3),
            "text_embedding_similarity": round(text_sim, 3),
            "behavioral_profile_similarity": round(behavioral_sim, 3),
            "raw_candidate_probability": round(probability, 3)
        }

        return round(probability, 4), factors


candidate_generator = MLCandidateGenerator()
