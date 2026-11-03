from typing import Annotated

from fastapi import APIRouter, Form, HTTPException, Request, status

from src.application.oauth.dtos import TokenRequest, TokenResponse
from src.application.oauth.grants import exchange_code, issue_client_token, refresh_tokens

router = APIRouter(prefix="/oauth", tags=["OAuth"])


@router.post("/token", status_code=status.HTTP_200_OK, response_model_exclude_none=True)
async def issue_token(
    request: Request[...],
    form: Annotated[TokenRequest, Form(discriminator="grant_type")],
) -> TokenResponse:

    match form.grant_type:
        case "authorization_code":
            return await exchange_code(form, ...)
        case "client_credentials":
            return await issue_client_token(form, ...)
        case "refresh_token":
            return await refresh_tokens(form, ...)

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={
            "error": "unsupported_grant_type",
            "error_description": f"Grant type {form.grant_type!r} is not supported."
        },
    )
