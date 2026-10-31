from typing import Annotated

from fastapi import APIRouter, Path, status

router = APIRouter(prefix="/federation", tags=["Federation"])


@router.get(
    "/{provider}/start",
    status_code=...,
    summary="Инициация потока аутентификации",
)
async def start_federation(
    provider: Annotated[str, Path(description="Ключ провайдера", examples=["vk", "yandex"])],
): ...


@router.get(
    "/{provider}/callback",
    status_code=status.HTTP_200_OK,
    summary="Обрабатывает callback и завершает поток",
)
async def handle_federation_callback(
    provider: Annotated[str, Path(description="Ключ провайдера", examples=["vk", "yandex"])],
): ...
