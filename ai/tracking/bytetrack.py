"""
ai/tracking/bytetrack.py
========================
Pure-Python ByteTrack-inspired multi-object tracker.

No external tracking libraries (lapx, etc.) are used.
Implements:
  - STrack      – single tracked object with simple Kalman-like motion model
  - BYTETracker – the two-stage IoU matching tracker

Usage
-----
    from ai.tracking.bytetrack import BYTETracker

    tracker = BYTETracker(track_thresh=0.5, track_buffer=30,
                          match_thresh=0.8, frame_rate=20)

    # Each call to update() returns a list of active tracks.
    tracked = tracker.update(detections, frame_size=(640, 480))
    for t in tracked:
        print(t["track_id"], t["bbox"], t["class_name"])
"""

from __future__ import annotations

from typing import List, Dict, Optional, Tuple
import numpy as np


# ---------------------------------------------------------------------------
# IoU helper
# ---------------------------------------------------------------------------

def iou(box1: List[float], box2: List[float]) -> float:
    """
    Compute Intersection-over-Union between two axis-aligned bounding boxes.

    Parameters
    ----------
    box1, box2 : [x1, y1, x2, y2]

    Returns
    -------
    float in [0, 1]
    """
    x1 = max(box1[0], box2[0])
    y1 = max(box1[1], box2[1])
    x2 = min(box1[2], box2[2])
    y2 = min(box1[3], box2[3])

    inter_w = max(0.0, x2 - x1)
    inter_h = max(0.0, y2 - y1)
    inter_area = inter_w * inter_h

    area1 = max(0.0, box1[2] - box1[0]) * max(0.0, box1[3] - box1[1])
    area2 = max(0.0, box2[2] - box2[0]) * max(0.0, box2[3] - box2[1])
    union_area = area1 + area2 - inter_area

    return inter_area / union_area if union_area > 0 else 0.0


# ---------------------------------------------------------------------------
# IoU cost matrix
# ---------------------------------------------------------------------------

def _iou_cost_matrix(tracks: List["STrack"], detections: List[Dict]) -> np.ndarray:
    """Return cost matrix (1 - IoU) of shape (len(tracks), len(detections))."""
    cost = np.ones((len(tracks), len(detections)), dtype=np.float32)
    for i, t in enumerate(tracks):
        for j, d in enumerate(detections):
            cost[i, j] = 1.0 - iou(t.predicted_bbox(), d["bbox"])
    return cost


# ---------------------------------------------------------------------------
# Greedy Hungarian matching (no external solver needed)
# ---------------------------------------------------------------------------

def _greedy_match(
    cost: np.ndarray, thresh: float
) -> Tuple[List[Tuple[int, int]], List[int], List[int]]:
    """
    Simple greedy assignment on the cost matrix.

    Returns
    -------
    matches       : list of (track_idx, det_idx)
    unmatched_trk : list of unmatched track indices
    unmatched_det : list of unmatched detection indices
    """
    if cost.size == 0:
        return [], list(range(cost.shape[0])), list(range(cost.shape[1]))

    matches: List[Tuple[int, int]] = []
    used_trk = set()
    used_det = set()

    # Sort (track, det) pairs by cost ascending
    flat = [(cost[i, j], i, j) for i in range(cost.shape[0]) for j in range(cost.shape[1])]
    flat.sort(key=lambda x: x[0])

    for c, i, j in flat:
        if c > thresh:
            break
        if i in used_trk or j in used_det:
            continue
        matches.append((i, j))
        used_trk.add(i)
        used_det.add(j)

    unmatched_trk = [i for i in range(cost.shape[0]) if i not in used_trk]
    unmatched_det = [j for j in range(cost.shape[1]) if j not in used_det]
    return matches, unmatched_trk, unmatched_det


# ---------------------------------------------------------------------------
# STrack – single tracked object
# ---------------------------------------------------------------------------

class STrack:
    """
    Represents one tracked object across frames.

    State vector (constant-velocity model): [cx, cy, w, h, vx, vy, 0, 0]
    We keep a simple exponential smoothing estimate rather than a full Kalman.
    """

    _next_id: int = 1  # class-level counter for globally unique IDs

    @classmethod
    def reset_id_counter(cls) -> None:
        cls._next_id = 1

    def __init__(
        self,
        bbox: List[float],
        score: float,
        class_name: str,
    ) -> None:
        self.track_id: int = STrack._next_id
        STrack._next_id += 1

        self.bbox: List[float] = list(map(float, bbox))  # [x1, y1, x2, y2]
        self.score: float = float(score)
        self.class_name: str = class_name

        # Velocity (exponential smoothing of displacement)
        self._vx: float = 0.0
        self._vy: float = 0.0
        self._alpha: float = 0.4   # smoothing factor for velocity

        self.age: int = 1          # frames since creation
        self.hits: int = 1         # consecutive matched frames
        self.time_since_update: int = 0   # frames since last match

        self._is_activated: bool = True

    # ------------------------------------------------------------------
    # Geometry helpers
    # ------------------------------------------------------------------

    @property
    def cx(self) -> float:
        return (self.bbox[0] + self.bbox[2]) / 2.0

    @property
    def cy(self) -> float:
        return (self.bbox[1] + self.bbox[3]) / 2.0

    def predicted_bbox(self) -> List[float]:
        """Return bbox predicted for the current frame using velocity."""
        x1, y1, x2, y2 = self.bbox
        x1p = x1 + self._vx
        y1p = y1 + self._vy
        x2p = x2 + self._vx
        y2p = y2 + self._vy
        return [x1p, y1p, x2p, y2p]

    # ------------------------------------------------------------------
    # State updates
    # ------------------------------------------------------------------

    def update(self, det_bbox: List[float], score: float) -> None:
        """Match with a detection: update position and velocity."""
        old_cx, old_cy = self.cx, self.cy

        self.bbox = list(map(float, det_bbox))
        self.score = float(score)

        # Update velocity with exponential smoothing
        disp_x = self.cx - old_cx
        disp_y = self.cy - old_cy
        self._vx = self._alpha * disp_x + (1 - self._alpha) * self._vx
        self._vy = self._alpha * disp_y + (1 - self._alpha) * self._vy

        self.hits += 1
        self.age += 1
        self.time_since_update = 0

    def predict(self) -> None:
        """Advance position by one frame using current velocity (called when unmatched)."""
        x1, y1, x2, y2 = self.bbox
        self.bbox = [x1 + self._vx, y1 + self._vy,
                     x2 + self._vx, y2 + self._vy]
        self.time_since_update += 1
        self.age += 1

    # ------------------------------------------------------------------
    # Output
    # ------------------------------------------------------------------

    def to_dict(self) -> Dict:
        return {
            "track_id": self.track_id,
            "bbox": [round(v, 1) for v in self.bbox],
            "score": round(self.score, 4),
            "class_name": self.class_name,
            "age": self.age,
        }

    def __repr__(self) -> str:
        return (
            f"<STrack id={self.track_id} cls={self.class_name!r} "
            f"age={self.age} tsu={self.time_since_update}>"
        )


# ---------------------------------------------------------------------------
# BYTETracker
# ---------------------------------------------------------------------------

class BYTETracker:
    """
    ByteTrack-inspired multi-object tracker using IoU matching in two stages:

    Stage 1 – match high-confidence detections to existing active tracks.
    Stage 2 – match low-confidence detections to unmatched tracks from stage 1.

    Parameters
    ----------
    track_thresh : float
        Detections with score >= track_thresh are "high-confidence".
    track_buffer : int
        Maximum frames a track can go without a match before being removed.
    match_thresh : float
        Maximum (1 - IoU) cost allowed for a valid match.
    frame_rate : int
        Expected frame rate (unused in matching but kept for API completeness).
    """

    def __init__(
        self,
        track_thresh: float = 0.5,
        track_buffer: int = 30,
        match_thresh: float = 0.8,
        frame_rate: int = 20,
    ) -> None:
        self.track_thresh = track_thresh
        self.track_buffer = track_buffer
        self.match_thresh = match_thresh
        self.frame_rate = frame_rate

        # Active tracks (regularly updated)
        self.tracked_tracks: List[STrack] = []
        # Lost tracks (recently unmatched, kept for re-identification)
        self.lost_tracks: List[STrack] = []

        self.frame_count: int = 0

    # ------------------------------------------------------------------
    # Main API
    # ------------------------------------------------------------------

    def update(
        self,
        detections: List[Dict],
        frame_size: Tuple[int, int] = (640, 480),
    ) -> List[Dict]:
        """
        Process one frame of detections and return current active tracks.

        Parameters
        ----------
        detections : list of dicts
            Each dict must contain:
              - ``bbox``       : [x1, y1, x2, y2]
              - ``score``      : float confidence
              - ``class_name`` : str
        frame_size : (width, height) – not used in matching but available
                     for future spatial normalisation.

        Returns
        -------
        list of dicts  with keys: track_id, bbox, score, class_name, age
        """
        self.frame_count += 1

        # ----------------------------------------------------------
        # 1. Split detections into high / low confidence pools
        # ----------------------------------------------------------
        high_dets = [d for d in detections if d.get("score", 0) >= self.track_thresh]
        low_dets  = [d for d in detections if d.get("score", 0) <  self.track_thresh]

        # ----------------------------------------------------------
        # 2. Predict new positions for all existing tracks
        # ----------------------------------------------------------
        all_tracks = self.tracked_tracks + self.lost_tracks
        for t in all_tracks:
            t.predict()

        # ----------------------------------------------------------
        # 3. Stage-1: match high-confidence detections to active tracks
        # ----------------------------------------------------------
        active = self.tracked_tracks  # reference

        unmatched_active: List[int] = []
        unmatched_high: List[int]   = []

        if active and high_dets:
            cost = _iou_cost_matrix(active, high_dets)
            matches_1, unmatched_active, unmatched_high = _greedy_match(
                cost, thresh=1.0 - self.match_thresh
            )
            for ti, di in matches_1:
                active[ti].update(high_dets[di]["bbox"], high_dets[di]["score"])
                active[ti].class_name = high_dets[di].get("class_name", active[ti].class_name)
        else:
            unmatched_active = list(range(len(active)))
            unmatched_high   = list(range(len(high_dets)))

        # ----------------------------------------------------------
        # 4. Stage-2: match low-confidence detections to unmatched
        #    active tracks (helps re-identify partially occluded objs)
        # ----------------------------------------------------------
        unmatched_active_after_s2: List[int] = []

        if unmatched_active and low_dets:
            remaining_tracks = [active[i] for i in unmatched_active]
            cost2 = _iou_cost_matrix(remaining_tracks, low_dets)
            matches_2, leftover_trk, _ = _greedy_match(
                cost2, thresh=1.0 - self.match_thresh
            )
            for ti, di in matches_2:
                orig_idx = unmatched_active[ti]
                active[orig_idx].update(low_dets[di]["bbox"], low_dets[di]["score"])
                active[orig_idx].class_name = low_dets[di].get("class_name", active[orig_idx].class_name)
            unmatched_active_after_s2 = [unmatched_active[i] for i in leftover_trk]
        else:
            unmatched_active_after_s2 = unmatched_active

        # ----------------------------------------------------------
        # 5. Stage-3: try to re-identify lost tracks with unmatched
        #    high-confidence detections
        # ----------------------------------------------------------
        new_det_indices = list(unmatched_high)  # indices into high_dets still unmatched
        remaining_lost  = self.lost_tracks

        matched_lost_det: Dict[int, int] = {}  # lost_idx -> high_det_idx

        if remaining_lost and new_det_indices:
            lost_dets_subset = [high_dets[i] for i in new_det_indices]
            cost3 = _iou_cost_matrix(remaining_lost, lost_dets_subset)
            matches_3, _, still_unmatched_high = _greedy_match(
                cost3, thresh=1.0 - self.match_thresh
            )
            for li, di in matches_3:
                real_di = new_det_indices[di]
                remaining_lost[li].update(high_dets[real_di]["bbox"], high_dets[real_di]["score"])
                remaining_lost[li].class_name = high_dets[real_di].get("class_name", remaining_lost[li].class_name)
                matched_lost_det[li] = real_di
            # Remaining unmatched high detections become new tracks
            truly_new_det_indices = [new_det_indices[i] for i in still_unmatched_high]
        else:
            truly_new_det_indices = new_det_indices

        # ----------------------------------------------------------
        # 6. Create new STrack objects for truly unmatched high-conf detections
        # ----------------------------------------------------------
        new_tracks: List[STrack] = []
        for di in truly_new_det_indices:
            d = high_dets[di]
            new_tracks.append(STrack(d["bbox"], d["score"], d.get("class_name", "unknown")))

        # ----------------------------------------------------------
        # 7. Move long-lost tracks to removed; move re-identified lost
        #    tracks back to active
        # ----------------------------------------------------------
        recovered: List[STrack] = []
        still_lost: List[STrack] = []
        for li, lt in enumerate(remaining_lost):
            if li in matched_lost_det:
                recovered.append(lt)
            elif lt.time_since_update <= self.track_buffer:
                still_lost.append(lt)
            # else: track is expired, drop it

        # ----------------------------------------------------------
        # 8. Move consistently unmatched active tracks to lost
        # ----------------------------------------------------------
        newly_lost: List[STrack] = []
        still_active: List[STrack] = []
        for i, t in enumerate(active):
            if i in unmatched_active_after_s2:
                if t.time_since_update <= self.track_buffer:
                    newly_lost.append(t)
                # else: drop (buffer exceeded while in active pool already)
            else:
                still_active.append(t)

        # ----------------------------------------------------------
        # 9. Compose updated track lists
        # ----------------------------------------------------------
        self.tracked_tracks = still_active + recovered + new_tracks
        self.lost_tracks    = still_lost + newly_lost

        # ----------------------------------------------------------
        # 10. Return only currently-active tracks
        # ----------------------------------------------------------
        return [t.to_dict() for t in self.tracked_tracks]

    def reset(self) -> None:
        """Clear all internal state (call between video sequences)."""
        self.tracked_tracks = []
        self.lost_tracks    = []
        self.frame_count    = 0
