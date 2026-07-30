from __future__ import annotations

import asyncio
import contextvars
import json
import logging
import time
import uuid
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Dict, List, Optional, Set, TypeVar, AsyncIterator
from contextlib import asynccontextmanager

import redis.asyncio as redis
from redis.asyncio.client import Pipeline
from pydantic import BaseModel, Field, ConfigDict

logger = logging.getLogger(__name__)

trace_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("trace_id", default=None)
span_id_var: contextvars.ContextVar[Optional[str]] = contextvars.ContextVar("span_id", default=None)


class EventStatus(str, Enum):
    PENDING = "pending"
    PROCESSING = "processing"
    COMPLETED = "completed"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"


class EventPriority(int, Enum):
    LOW = 0
    NORMAL = 50
    HIGH = 100
    CRITICAL = 200


@dataclass(slots=True)
class Event:
    event_type: str
    payload: Dict[str, Any]
    trace_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    span_id: str = field(default_factory=lambda: str(uuid.uuid4())[:16])
    parent_span_id: Optional[str] = None
    priority: EventPriority = EventPriority.NORMAL
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    headers: Dict[str, str] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    retry_count: int = 0
    max_retries: int = 3
    status: EventStatus = EventStatus.PENDING
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    stream_id: Optional[str] = None

    def to_stream_dict(self) -> Dict[str, str]:
        return {
            "id": self.id,
            "event_type": self.event_type,
            "payload": json.dumps(self.payload),
            "trace_id": self.trace_id,
            "span_id": self.span_id,
            "parent_span_id": self.parent_span_id or "",
            "priority": str(self.priority.value),
            "timestamp": self.timestamp.isoformat(),
            "headers": json.dumps(self.headers),
            "metadata": json.dumps(self.metadata),
            "retry_count": str(self.retry_count),
            "max_retries": str(self.max_retries),
            "status": self.status.value,
        }

    @classmethod
    def from_stream_dict(cls, data: Dict[str, str], stream_id: str) -> Event:
        return cls(
            id=data.get("id", str(uuid.uuid4())),
            event_type=data["event_type"],
            payload=json.loads(data["payload"]),
            trace_id=data.get("trace_id", str(uuid.uuid4())),
            span_id=data.get("span_id", str(uuid.uuid4())[:16]),
            parent_span_id=data.get("parent_span_id") or None,
            priority=EventPriority(int(data.get("priority", str(EventPriority.NORMAL.value)))),
            timestamp=datetime.fromisoformat(data["timestamp"]),
            headers=json.loads(data.get("headers", "{}")),
            metadata=json.loads(data.get("metadata", "{}")),
            retry_count=int(data.get("retry_count", "0")),
            max_retries=int(data.get("max_retries", "3")),
            status=EventStatus(data.get("status", EventStatus.PENDING.value)),
            stream_id=stream_id,
        )


class EventBusConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    redis_url: str = "redis://localhost:6379/0"
    consumer_group: str = "raphael-eventbus"
    consumer_name: Optional[str] = None
    max_concurrent_streams: int = 10
    claim_min_idle_time: int = 30000
    block_timeout: int = 5000
    max_retries: int = 3
    retry_backoff_base: float = 1.0
    retry_backoff_max: float = 60.0
    dead_letter_stream: str = "raphael:dlq"
    health_check_interval: int = 30
    metrics_enabled: bool = True
    stream_max_len: int = 10000
    auto_create_streams: bool = True


class EventBusMetrics(BaseModel):
    events_published: int = 0
    events_consumed: int = 0
    events_failed: int = 0
    events_retried: int = 0
    events_dead_lettered: int = 0
    events_replayed: int = 0
    publish_latency_ms: float = 0.0
    consume_latency_ms: float = 0.0
    active_consumers: int = 0
    pending_messages: int = 0
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


HandlerType = TypeVar("HandlerType", bound=Callable[[Event], Any])


class EventBus:
    _BUFFER_MAX_SIZE = 1000

    def __init__(self, config: Optional[EventBusConfig] = None):
        self.config = config or EventBusConfig()
        self._redis: Optional[redis.Redis] = None
        self._handlers: Dict[str, List[HandlerType]] = defaultdict(list)
        self._consumer_tasks: Dict[str, asyncio.Task] = {}
        self._running = False
        self._metrics = EventBusMetrics()
        self._metrics_lock = asyncio.Lock()
        self._health_check_task: Optional[asyncio.Task] = None
        self._rebalance_lock = asyncio.Lock()
        self._consumer_id = self.config.consumer_name or f"consumer-{uuid.uuid4().hex[:8]}"
        self._subscribed_streams: Set[str] = set()
        self._pending_acks: Dict[str, Dict[str, Event]] = defaultdict(dict)
        self._buffer: Dict[str, List[Event]] = defaultdict(list)
        self._startup_complete = asyncio.Event()
        self._buffer_lock = asyncio.Lock()

    async def connect(self) -> None:
        if self._redis is not None:
            return
        self._redis = redis.from_url(
            self.config.redis_url,
            encoding="utf-8",
            decode_responses=True,
            max_connections=self.config.max_concurrent_streams + 5,
        )
        await self._redis.ping()
        logger.info(f"EventBus connected to Redis at {self.config.redis_url}")

    async def disconnect(self) -> None:
        self._running = False
        for task in self._consumer_tasks.values():
            task.cancel()
        if self._consumer_tasks:
            await asyncio.gather(*self._consumer_tasks.values(), return_exceptions=True)
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        if self._redis:
            await self._redis.close()
            self._redis = None
        logger.info("EventBus disconnected")

    async def __aenter__(self) -> EventBus:
        await self.connect()
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb) -> None:
        await self.disconnect()

    @property
    def redis(self) -> redis.Redis:
        if self._redis is None:
            raise RuntimeError("EventBus not connected. Call connect() first.")
        return self._redis

    def subscribe(self, event_type: str, handler: HandlerType) -> None:
        self._handlers[event_type].append(handler)
        logger.debug(f"Subscribed handler for event_type: {event_type}")
        if not self._startup_complete.is_set():
            asyncio.create_task(self._flush_buffer(event_type))

    def unsubscribe(self, event_type: str, handler: HandlerType) -> bool:
        if event_type in self._handlers and handler in self._handlers[event_type]:
            self._handlers[event_type].remove(handler)
            return True
        return False

    async def _flush_buffer(self, event_type: str) -> None:
        """Flush buffered events for an event_type to handlers.
        
        Assumes startup sequence: services publish events during startup,
        then call signal_startup_complete() when ready. Subscribers may
        register before or after startup_complete. If before, buffer flushes
        on subscribe. If after, buffer flushes on signal_startup_complete().
        """
        async with self._buffer_lock:
            buffered = self._buffer.get(event_type, [])
            if not buffered:
                return
            self._buffer[event_type] = []

        handlers = self._handlers.get(event_type, [])
        if not handlers:
            logger.debug(f"No handlers for buffered events {event_type}, re-buffering {len(buffered)} events")
            async with self._buffer_lock:
                self._buffer[event_type].extend(buffered)
            return

        logger.info(f"Flushing {len(buffered)} buffered events for {event_type} to {len(handlers)} handlers")
        for event in buffered:
            for handler in handlers:
                try:
                    if asyncio.iscoroutinefunction(handler):
                        await handler(event)
                    else:
                        handler(event)
                except Exception as e:
                    logger.error(f"Error handling buffered event {event.id}: {e}")
                    await self._increment_metric("events_failed")

    async def signal_startup_complete(self) -> None:
        """Signal startup is complete and flush all buffered events.
        
        Call this after all services have started and subscribers are registered.
        Flushes all buffered events to their handlers.
        """
        if self._startup_complete.is_set():
            logger.warning("startup_complete already signaled")
            return

        self._startup_complete.set()
        logger.info("Startup complete signaled, flushing all buffered events")

        async with self._buffer_lock:
            event_types = list(self._buffer.keys())

        for event_type in event_types:
            await self._flush_buffer(event_type)

    async def publish(
        self,
        event_type: str,
        payload: Dict[str, Any],
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
        parent_span_id: Optional[str] = None,
        priority: EventPriority = EventPriority.NORMAL,
        headers: Optional[Dict[str, str]] = None,
        metadata: Optional[Dict[str, Any]] = None,
        max_retries: Optional[int] = None,
    ) -> Event:
        await self.connect()

        current_trace_id = trace_id or trace_id_var.get() or str(uuid.uuid4())
        current_span_id = span_id or span_id_var.get() or str(uuid.uuid4())[:16]
        current_parent_span_id = parent_span_id or (span_id_var.get() if span_id is None else None)

        event = Event(
            event_type=event_type,
            payload=payload,
            trace_id=current_trace_id,
            span_id=current_span_id,
            parent_span_id=current_parent_span_id,
            priority=priority,
            headers=headers or {},
            metadata=metadata or {},
            max_retries=max_retries or self.config.max_retries,
        )

        if not self._startup_complete.is_set() and not self._handlers.get(event_type):
            async with self._buffer_lock:
                buffer = self._buffer[event_type]
                if len(buffer) >= self._BUFFER_MAX_SIZE:
                    buffer.pop(0)
                buffer.append(event)
            logger.debug(f"Buffered event {event.id} for event_type {event_type} (startup not complete, no handlers)")
            return event

        stream_key = f"raphael:events:{event_type}"
        if self.config.auto_create_streams:
            await self._ensure_stream_exists(stream_key)

        start_time = time.perf_counter()
        try:
            stream_id = await self.redis.xadd(
                stream_key,
                event.to_stream_dict(),
                maxlen=self.config.stream_max_len,
                approximate=True,
            )
            event.stream_id = stream_id
            await self._increment_metric("events_published")
            await self._update_publish_latency(time.perf_counter() - start_time)
            logger.debug(f"Published event {event.id} to {stream_key} with stream_id {stream_id}")
            return event
        except Exception as e:
            await self._increment_metric("events_failed")
            logger.error(f"Failed to publish event: {e}")
            raise

    async def publish_batch(
        self,
        events: List[Event],
        pipeline: Optional[Pipeline] = None,
    ) -> List[str]:
        await self.connect()
        if not events:
            return []

        use_pipeline = pipeline is not None
        pipe = pipeline or self.redis.pipeline()

        stream_keys = set()
        for event in events:
            stream_key = f"raphael:events:{event.event_type}"
            stream_keys.add(stream_key)
            if self.config.auto_create_streams:
                await self._ensure_stream_exists(stream_key)
            pipe.xadd(stream_key, event.to_stream_dict(), maxlen=self.config.stream_max_len, approximate=True)

        start_time = time.perf_counter()
        results = await pipe.execute()
        await self._increment_metric("events_published", len(events))
        await self._update_publish_latency(time.perf_counter() - start_time)

        for event, stream_id in zip(events, results):
            event.stream_id = stream_id

        logger.debug(f"Published batch of {len(events)} events to streams: {stream_keys}")
        return results

    async def _ensure_stream_exists(self, stream_key: str) -> None:
        try:
            await self.redis.xinfo_stream(stream_key)
        except redis.ResponseError:
            await self.redis.xadd(stream_key, {"_init": "1"}, maxlen=1)
            await self.redis.xdel(stream_key, "0-0")
            await self._create_consumer_group(stream_key)

    async def _create_consumer_group(self, stream_key: str) -> None:
        try:
            await self.redis.xgroup_create(stream_key, self.config.consumer_group, id="0", mkstream=True)
        except redis.ResponseError as e:
            if "BUSYGROUP" not in str(e):
                raise

    async def start_consumer(
        self,
        event_types: List[str],
        batch_size: int = 10,
        auto_ack: bool = True,
    ) -> None:
        if self._running:
            logger.warning("Consumer already running")
            return

        await self.connect()
        self._running = True

        for event_type in event_types:
            stream_key = f"raphael:events:{event_type}"
            await self._ensure_stream_exists(stream_key)
            self._subscribed_streams.add(stream_key)

        self._health_check_task = asyncio.create_task(self._health_check_loop())

        for event_type in event_types:
            stream_key = f"raphael:events:{event_type}"
            task = asyncio.create_task(
                self._consume_stream(stream_key, event_type, batch_size, auto_ack)
            )
            self._consumer_tasks[stream_key] = task

        await self._increment_metric("active_consumers", len(event_types))
        logger.info(f"Started consumer for event types: {event_types}")

    async def stop_consumer(self) -> None:
        self._running = False
        for task in self._consumer_tasks.values():
            task.cancel()
        if self._consumer_tasks:
            await asyncio.gather(*self._consumer_tasks.values(), return_exceptions=True)
        self._consumer_tasks.clear()
        if self._health_check_task:
            self._health_check_task.cancel()
            try:
                await self._health_check_task
            except asyncio.CancelledError:
                pass
        await self._increment_metric("active_consumers", -len(self._subscribed_streams))
        logger.info("Stopped consumer")

    async def _consume_stream(
        self,
        stream_key: str,
        event_type: str,
        batch_size: int,
        auto_ack: bool,
    ) -> None:
        while self._running:
            try:
                await self._claim_pending_messages(stream_key)
                messages = await self.redis.xreadgroup(
                    self.config.consumer_group,
                    self._consumer_id,
                    {stream_key: ">"},
                    count=batch_size,
                    block=self.config.block_timeout,
                )

                if not messages:
                    continue

                for stream_name, stream_messages in messages:
                    for msg_id, msg_data in stream_messages:
                        event = Event.from_stream_dict(msg_data, msg_id)
                        await self._process_event(event, stream_key, msg_id, auto_ack)

            except asyncio.CancelledError:
                break
            except redis.ConnectionError:
                await asyncio.sleep(1)
            except Exception as e:
                logger.error(f"Error consuming from {stream_key}: {e}")
                await asyncio.sleep(1)

    async def _claim_pending_messages(self, stream_key: str) -> None:
        try:
            pending = await self.redis.xpending_range(
                stream_key,
                self.config.consumer_group,
                min="-",
                max="+",
                count=100,
            )
            for p in pending:
                if p["time_since_delivered"] >= self.config.claim_min_idle_time:
                    claimed = await self.redis.xclaim(
                        stream_key,
                        self.config.consumer_group,
                        self._consumer_id,
                        self.config.claim_min_idle_time,
                        [p["message_id"]],
                    )
                    for msg_id, msg_data in claimed:
                        event = Event.from_stream_dict(msg_data, msg_id)
                        await self._process_event(event, stream_key, msg_id, auto_ack=True)
        except Exception as e:
            logger.debug(f"Claim pending failed for {stream_key}: {e}")

    async def _process_event(
        self,
        event: Event,
        stream_key: str,
        msg_id: str,
        auto_ack: bool,
    ) -> None:
        start_time = time.perf_counter()
        handlers = self._handlers.get(event.event_type, [])

        if not handlers:
            logger.warning(f"No handlers for event_type: {event.event_type}")
            if auto_ack:
                await self.redis.xack(stream_key, self.config.consumer_group, msg_id)
            return

        token_trace = trace_id_var.set(event.trace_id)
        token_span = span_id_var.set(event.span_id)

        try:
            event.status = EventStatus.PROCESSING
            await self._increment_metric("events_consumed")

            for handler in handlers:
                if asyncio.iscoroutinefunction(handler):
                    await handler(event)
                else:
                    handler(event)

            event.status = EventStatus.COMPLETED
            if auto_ack:
                await self.redis.xack(stream_key, self.config.consumer_group, msg_id)
                await self._cleanup_pending_ack(stream_key, msg_id)

            await self._update_consume_latency(time.perf_counter() - start_time)

        except Exception as e:
            await self._handle_event_failure(event, stream_key, msg_id, e, auto_ack)
        finally:
            trace_id_var.reset(token_trace)
            span_id_var.reset(token_span)

    async def _handle_event_failure(
        self,
        event: Event,
        stream_key: str,
        msg_id: str,
        error: Exception,
        auto_ack: bool,
    ) -> None:
        event.retry_count += 1
        logger.warning(
            f"Event {event.id} failed (attempt {event.retry_count}/{event.max_retries}): {error}"
        )

        if event.retry_count >= event.max_retries:
            event.status = EventStatus.DEAD_LETTER
            await self._send_to_dlq(event, str(error))
            await self._increment_metric("events_dead_lettered")
            if auto_ack:
                await self.redis.xack(stream_key, self.config.consumer_group, msg_id)
        else:
            event.status = EventStatus.FAILED
            await self._increment_metric("events_retried")
            backoff = min(
                self.config.retry_backoff_base * (2 ** (event.retry_count - 1)),
                self.config.retry_backoff_max,
            )
            await asyncio.sleep(backoff)
            if auto_ack:
                await self.redis.xack(stream_key, self.config.consumer_group, msg_id)
                await self._cleanup_pending_ack(stream_key, msg_id)
            await self.publish(
                event.event_type,
                event.payload,
                trace_id=event.trace_id,
                span_id=event.span_id,
                parent_span_id=event.parent_span_id,
                priority=event.priority,
                headers=event.headers,
                metadata={**event.metadata, "retry_of": event.id},
                max_retries=event.max_retries,
            )

    async def _send_to_dlq(self, event: Event, error: str) -> None:
        dlq_event = Event(
            event_type=f"dlq.{event.event_type}",
            payload={
                "original_event": event.to_stream_dict(),
                "error": error,
                "failed_at": datetime.now(timezone.utc).isoformat(),
            },
            trace_id=event.trace_id,
            span_id=event.span_id,
            priority=EventPriority.CRITICAL,
        )
        try:
            await self.redis.xadd(
                self.config.dead_letter_stream,
                dlq_event.to_stream_dict(),
                maxlen=self.config.stream_max_len,
            )
        except Exception as e:
            logger.error(f"Failed to send event to DLQ: {e}")

    async def replay(
        self,
        event_type: str,
        from_id: str = "0",
        to_id: str = "+",
        count: Optional[int] = None,
        filter_fn: Optional[Callable[[Event], bool]] = None,
    ) -> int:
        await self.connect()
        stream_key = f"raphael:events:{event_type}"

        messages = await self.redis.xrange(stream_key, min=from_id, max=to_id, count=count or 1000)
        replayed = 0

        for msg_id, msg_data in messages:
            event = Event.from_stream_dict(msg_data, msg_id)
            if filter_fn and not filter_fn(event):
                continue

            new_event = Event(
                event_type=event.event_type,
                payload=event.payload,
                trace_id=event.trace_id,
                span_id=str(uuid.uuid4())[:16],
                parent_span_id=event.span_id,
                priority=event.priority,
                headers=event.headers,
                metadata={**event.metadata, "replayed_from": event.id, "replayed_at": datetime.now(timezone.utc).isoformat()},
                max_retries=event.max_retries,
            )

            await self.publish(
                new_event.event_type,
                new_event.payload,
                trace_id=new_event.trace_id,
                span_id=new_event.span_id,
                parent_span_id=new_event.parent_span_id,
                priority=new_event.priority,
                headers=new_event.headers,
                metadata=new_event.metadata,
                max_retries=new_event.max_retries,
            )
            replayed += 1

        await self._increment_metric("events_replayed", replayed)
        logger.info(f"Replayed {replayed} events from {stream_key}")
        return replayed

    async def replay_from_dlq(
        self,
        event_type: Optional[str] = None,
        count: Optional[int] = None,
    ) -> int:
        await self.connect()
        messages = await self.redis.xrange(
            self.config.dead_letter_stream,
            min="0",
            max="+",
            count=count or 1000,
        )
        replayed = 0

        for msg_id, msg_data in messages:
            dlq_event = Event.from_stream_dict(msg_data, msg_id)
            original_data = json.loads(dlq_event.payload.get("original_event", "{}"))
            original_event_type = original_data.get("event_type", "").replace("dlq.", "")

            if event_type and original_event_type != event_type:
                continue

            original_payload = json.loads(original_data.get("payload", "{}"))
            await self.publish(
                original_event_type,
                original_payload,
                trace_id=original_data.get("trace_id"),
                priority=EventPriority(int(original_data.get("priority", str(EventPriority.NORMAL.value)))),
                headers=json.loads(original_data.get("headers", "{}")),
                metadata={**json.loads(original_data.get("metadata", "{}")), "dlq_replay": True},
            )
            await self.redis.xdel(self.config.dead_letter_stream, msg_id)
            replayed += 1

        logger.info(f"Replayed {replayed} events from DLQ")
        return replayed

    async def health_check(self) -> Dict[str, Any]:
        await self.connect()
        try:
            await self.redis.ping()
            info = await self.redis.info("memory")
            consumers = await self._get_active_consumers()
            pending = await self._get_total_pending()

            return {
                "status": "healthy",
                "redis_connected": True,
                "memory_used_bytes": info.get("used_memory", 0),
                "active_consumers": len(consumers),
                "pending_messages": pending,
                "subscribed_streams": list(self._subscribed_streams),
                "consumer_id": self._consumer_id,
                "consumer_group": self.config.consumer_group,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
        except Exception as e:
            return {
                "status": "unhealthy",
                "redis_connected": False,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

    async def get_metrics(self) -> EventBusMetrics:
        async with self._metrics_lock:
            pending = await self._get_total_pending()
            self._metrics.pending_messages = pending
            self._metrics.last_updated = datetime.now(timezone.utc)
            return self._metrics.model_copy()

    async def _get_active_consumers(self) -> List[str]:
        consumers = set()
        for stream in self._subscribed_streams:
            try:
                info = await self.redis.xinfo_consumers(stream, self.config.consumer_group)
                consumers.update(c["name"] for c in info)
            except Exception:
                pass
        return list(consumers)

    async def _get_total_pending(self) -> int:
        total = 0
        for stream in self._subscribed_streams:
            try:
                pending = await self.redis.xpending(stream, self.config.consumer_group)
                total += pending.get("pending", 0)
            except Exception:
                pass
        return total

    async def _health_check_loop(self) -> None:
        while self._running:
            try:
                health = await self.health_check()
                if health["status"] != "healthy":
                    logger.warning(f"Health check failed: {health}")
            except Exception as e:
                logger.error(f"Health check error: {e}")
            await asyncio.sleep(self.config.health_check_interval)

    async def _increment_metric(self, name: str, value: int = 1) -> None:
        if not self.config.metrics_enabled:
            return
        async with self._metrics_lock:
            current = getattr(self._metrics, name, 0)
            setattr(self._metrics, name, current + value)

    async def _update_publish_latency(self, latency_seconds: float) -> None:
        if not self.config.metrics_enabled:
            return
        async with self._metrics_lock:
            current = self._metrics.publish_latency_ms
            count = self._metrics.events_published
            self._metrics.publish_latency_ms = ((current * (count - 1)) + (latency_seconds * 1000)) / count if count > 0 else latency_seconds * 1000

    async def _update_consume_latency(self, latency_seconds: float) -> None:
        if not self.config.metrics_enabled:
            return
        async with self._metrics_lock:
            current = self._metrics.consume_latency_ms
            count = self._metrics.events_consumed
            self._metrics.consume_latency_ms = ((current * (count - 1)) + (latency_seconds * 1000)) / count if count > 0 else latency_seconds * 1000

    async def _cleanup_pending_ack(self, stream_key: str, msg_id: str) -> None:
        if stream_key in self._pending_acks and msg_id in self._pending_acks[stream_key]:
            del self._pending_acks[stream_key][msg_id]

    @asynccontextmanager
    async def trace_context(
        self,
        trace_id: Optional[str] = None,
        span_id: Optional[str] = None,
    ) -> AsyncIterator[None]:
        token_trace = trace_id_var.set(trace_id or str(uuid.uuid4()))
        token_span = span_id_var.set(span_id or str(uuid.uuid4())[:16])
        try:
            yield
        finally:
            trace_id_var.reset(token_trace)
            span_id_var.reset(token_span)

    def get_current_trace_id(self) -> Optional[str]:
        return trace_id_var.get()

    def get_current_span_id(self) -> Optional[str]:
        return span_id_var.get()

    async def create_consumer_group(self, stream_key: str, group_name: str) -> bool:
        await self.connect()
        try:
            await self.redis.xgroup_create(stream_key, group_name, id="0", mkstream=True)
            return True
        except redis.ResponseError as e:
            if "BUSYGROUP" in str(e):
                return False
            raise

    async def delete_consumer_group(self, stream_key: str, group_name: str) -> bool:
        await self.connect()
        try:
            await self.redis.xgroup_destroy(stream_key, group_name)
            return True
        except redis.ResponseError:
            return False

    async def list_streams(self, pattern: str = "raphael:events:*") -> List[str]:
        await self.connect()
        streams = []
        async for key in self.redis.scan_iter(match=pattern, count=100):
            streams.append(key)
        return streams

    async def get_stream_info(self, stream_key: str) -> Dict[str, Any]:
        await self.connect()
        try:
            info = await self.redis.xinfo_stream(stream_key)
            groups = await self.redis.xinfo_groups(stream_key)
            return {
                "stream": stream_key,
                "length": info["length"],
                "radix_tree_keys": info["radix-tree-keys"],
                "radix_tree_nodes": info["radix-tree-nodes"],
                "groups": groups,
                "first_entry": info.get("first-entry"),
                "last_entry": info.get("last-entry"),
            }
        except redis.ResponseError:
            return {"stream": stream_key, "exists": False}

    async def trim_stream(self, stream_key: str, max_len: int) -> int:
        await self.connect()
        return await self.redis.xtrim(stream_key, maxlen=max_len, approximate=True)

    async def get_pending_messages(
        self,
        stream_key: str,
        count: int = 100,
    ) -> List[Dict[str, Any]]:
        await self.connect()
        pending = await self.redis.xpending_range(
            stream_key,
            self.config.consumer_group,
            min="-",
            max="+",
            count=count,
        )
        return pending