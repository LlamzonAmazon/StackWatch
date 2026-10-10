"""Event emission utilities."""

from datetime import UTC, datetime

from app import store
from app.schema import Event, EventLevel, EventStage


def emit_event(
    stage: EventStage,
    level: EventLevel,
    message: str,
    target_id: str,
    run_id: str | None = None,
    ref_id: str | None = None,
) -> Event:
    event = Event(
        target_id=target_id,
        run_id=run_id,
        stage=stage,
        level=level,
        message=message,
        ref_id=ref_id,
        ts=datetime.now(UTC).replace(tzinfo=None),
    )
    store.insert_event(event)
    return event


def make_emit(target_id: str, run_id: str | None = None):
    """Create an emit callback for a pillar."""
    def emit(stage: str, level: str, message: str, ref_id: str | None = None) -> None:
        emit_event(stage, level, message, target_id, run_id, ref_id)
    return emit
