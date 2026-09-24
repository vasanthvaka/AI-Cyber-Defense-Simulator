from abc import ABC, abstractmethod
from collections import deque

from agents.message_schema import (
    AgentMessage,
    VALID_AGENT_NAMES
)


class BaseAgent(ABC):

    def __init__(self, agent_name):

        if agent_name not in VALID_AGENT_NAMES:
            raise ValueError(
                f"Invalid agent name: "
                f"{agent_name}"
            )

        self.agent_name = agent_name
        self.inbox = deque()
        self.outbox = deque()

        self.processed_message_count = 0
        self.failed_message_count = 0

    def receive(self, message):

        if not isinstance(message, AgentMessage):
            raise TypeError(
                "Agent can only receive "
                "AgentMessage objects"
            )

        if message.recipient != self.agent_name:
            raise ValueError(
                f"Message recipient is "
                f"{message.recipient}, not "
                f"{self.agent_name}"
            )

        message.mark_delivered()
        self.inbox.append(message)

    def process_next(self):

        if not self.inbox:
            return None

        message = self.inbox.popleft()

        try:
            result = self.handle_message(message)

            replies = self._normalize_replies(
                result
            )

            message.mark_processed()
            self.processed_message_count += 1

            self.outbox.extend(replies)

            return result

        except Exception:

            message.mark_failed()
            self.failed_message_count += 1
            raise

    def process_all(self):

        replies = []

        while self.inbox:

            result = self.process_next()

            if result is None:
                continue

            if isinstance(result, AgentMessage):
                replies.append(result)
            else:
                replies.extend(result)

        return replies

    def create_message(
        self,
        message_type,
        recipient,
        payload,
        correlation_id=None,
        priority="NORMAL",
        parent_message_id=None
    ):

        return AgentMessage(
            message_type=message_type,
            sender=self.agent_name,
            recipient=recipient,
            payload=payload,
            correlation_id=correlation_id,
            priority=priority,
            parent_message_id=parent_message_id
        )

    def take_next_outgoing_message(self):

        if not self.outbox:
            return None

        return self.outbox.popleft()

    @staticmethod
    def _normalize_replies(result):

        if result is None:
            return []

        if isinstance(result, AgentMessage):
            return [
                result
            ]

        if isinstance(result, list):

            if not all(
                isinstance(reply, AgentMessage)
                for reply in result
            ):
                raise TypeError(
                    "Every reply must be an "
                    "AgentMessage"
                )

            return result

        raise TypeError(
            "Agent handlers must return an "
            "AgentMessage, a list of "
            "AgentMessage objects, or None"
        )

    @abstractmethod
    def handle_message(self, message):

        raise NotImplementedError