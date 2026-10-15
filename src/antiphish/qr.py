"""Bounded QR decoding with fallbacks even when multi-detection returns false."""
from __future__ import annotations

import time


def decode(image, *, seconds=2.5) -> list[str]:
    import cv2
    import numpy as np
    image = image.convert('L')
    image.thumbnail((1800, 1800))
    original = np.asarray(image)
    detector = cv2.QRCodeDetector()
    deadline = time.monotonic() + seconds
    values = []
    # Ordinary, inverted, contrast-normalized and binarized codes. Avoid an
    # unbounded augmentation search on a random screenshot.
    variants = [original, 255 - original, cv2.equalizeHist(original)]
    _, threshold = cv2.threshold(original, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    variants.extend([threshold, 255 - threshold])
    for array in variants:
        if time.monotonic() > deadline:
            break
        try:
            ok, decoded, _, _ = detector.detectAndDecodeMulti(array)
            if ok:
                values.extend(v for v in decoded if v)
            if not values:
                value, _, _ = detector.detectAndDecode(array)
                if value:
                    values.append(value)
        except cv2.error:
            continue
        if values:
            break
    return list(dict.fromkeys(values))[:20]
