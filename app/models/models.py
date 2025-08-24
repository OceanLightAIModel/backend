from sqlalchemy.orm import Mapped, mapped_column, relationship 
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Integer, String, DateTime, ForeignKey, Index, func, Enum, text, Boolean, UniqueConstraint
from typing import List
import datetime

base = declarative_base()
class Users(base):
    __tablename__ = "users"
    user_id : Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username : Mapped[str] = mapped_column(String(100), nullable=False)
    password_hash : Mapped[str] = mapped_column(String(255), nullable=False)
    email : Mapped[str] = mapped_column(String(100), nullable=False, unique=True)
    created_at : Mapped[datetime.datetime] = mapped_column(DateTime, default=func.now())
    updated_at : Mapped[datetime.datetime] = mapped_column(DateTime, default=func.now(), onupdate=func.now())

    refresh_tokens: Mapped[List["RefreshToken"]] = relationship(back_populates="users", cascade="all, delete-orphan")
    threads: Mapped[List["Thread"]] = relationship(back_populates="users", cascade="all, delete-orphan")


class RefreshToken(base):
    __tablename__ = "refresh_tokens"
    __table_args__ = (
         Index("idx_rt_user", "user_id"),
        Index("idx_rt_revoked_expires", "revoked", "expires_at"),
        Index("idx_refresh_token_id", "user_id"),         
        UniqueConstraint("token_hash", name="uq_refresh_tokens_token_hash"),
        )

    refresh_token_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    token_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.user_id"), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, server_default=func.now(), nullable=False)
    expires_at: Mapped[datetime.datetime] = mapped_column(DateTime, nullable=False)
    last_used_at: Mapped[datetime.datetime | None] = mapped_column(DateTime, nullable=True)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, server_default=text("0"))
    replaced_by: Mapped[str | None] = mapped_column(String(64), nullable=True)

    users: Mapped["Users"] = relationship(back_populates="refresh_tokens")

class Thread(base):
    __tablename__ = "threads"
    __table_args__ = (
        Index("thread_user_id", "user_id"),
        )
    thread_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    thread_title: Mapped[str] = mapped_column(String(100), nullable=False) 
    user_id: Mapped[int] = mapped_column(Integer, ForeignKey("users.user_id"), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=func.now())

    users: Mapped["Users"] = relationship(back_populates="threads")
    messages: Mapped[List["Message"]] = relationship(back_populates='thread', cascade="all, delete, delete-orphan")

class Message(base):
    __tablename__ = "messages"
    __table_args__ = (
        Index("message_thread_id", "thread_id"),
        )
    message_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    thread_id: Mapped[int] = mapped_column(Integer, ForeignKey("threads.thread_id"))
    sender_type: Mapped[str] = mapped_column(Enum("user", "assistant"), nullable=False)
    content: Mapped[str] = mapped_column(String(500), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=func.now())

    thread: Mapped["Thread"] = relationship(back_populates="messages")
    images: Mapped[list["Image"]] = relationship(back_populates="message", cascade="all, delete-orphan")

class Image(base):
    __tablename__ = "images"
    image_id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    message_id: Mapped[int] = mapped_column(Integer, ForeignKey("messages.message_id"), nullable=False)
    image_url: Mapped[str] = mapped_column(String(255), nullable=False)
    created_at: Mapped[datetime.datetime] = mapped_column(DateTime, default=func.now())

    message: Mapped["Message"] = relationship(back_populates="images")

    