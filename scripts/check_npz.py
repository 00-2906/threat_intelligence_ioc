import numpy as np
from pathlib import Path

npz_path = Path(__file__).resolve().parent.parent / "reference_embeddings.npz"
data = np.load(npz_path, allow_pickle=True)
print(data.files)