"""VaultScope core package.

Analysis pipeline stages 1-5. Each subpackage maps to a pipeline stage from
the product spec (docs/VaultScope_Product_Spec.docx, Section 3):

    ingestion   -> Stage 1  Ingestion Engine            (P1)
    ike_parser  -> Stage 2  IKE Parser                  (P2)
    flow        -> Stage 3  ESP/AH Flow Feature Extractor (P2)
    classifiers -> Stage 4a Protocol/Crypto Classifier   (P2)
                   Stage 4b Traffic-Type Classifier      (P2)
    rules       -> Stage 4c Security Rule Engine         (P3)
"""

__version__ = "0.1.0"
