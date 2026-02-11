# TODO

## Remaining issues from connector integration review

5. RabbitMQ dead-letter visibility is incomplete for per-webhook queues
- What is wrong:
  Admin dead-letter API currently reads only channel-level DLQ, but failures are now stored in per-webhook DLQs. Result: dead-letter endpoint can report empty even when per-webhook DLQs contain messages.
- Where to look / fix ideas:
  Check dead-letter read path in `/Users/eduards.marhelis/Projects/EM/14_webhook/core-webhook-module/src/webhook_connect/admin_api.py` (`/channels/{channel}/dead-letters`).
  Update RabbitMQ implementation in `/Users/eduards.marhelis/Projects/EM/14_webhook/core-webhook-module/src/webhook_connect/buffer/rabbitmq_buffer.py` (`get_dead_letters`) to aggregate across known webhook IDs (from ChannelManager tracking).
  Consider adding/using a buffer method that accepts `webhook_ids` and merges/sorts results.
  Add tests covering mixed dead letters across multiple webhook queues.

6. Per-webhook RabbitMQ tests are out of sync with current architecture
- What is wrong:
  Several tests still assert collector-queue behavior (`_collector_name`, raw consumer tag expectations, `basic_cancel`, collector deletion), but implementation now uses direct per-webhook consumers and composite channel tags.
- Where to look / fix ideas:
  Update `/Users/eduards.marhelis/Projects/EM/14_webhook/core-webhook-module/tests/unit/test_webhook_connect_per_webhook_queues.py` to assert current behavior:
  - no collector queue assumptions
  - `subscribe()` returns `channel_sub:{channel}`
  - `unsubscribe()` cancels queue consumers via tracked queue refs
  - queue depth uses temporary AMQP channel path
  Keep security coverage in `/Users/eduards.marhelis/Projects/EM/14_webhook/core-webhook-module/tests/unit/test_webhook_connect_per_webhook_queues_security_audit.py` aligned with new lifecycle model.
