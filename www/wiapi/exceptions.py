from fastapi import Request
from fastapi.exceptions import HTTPException, RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.encoders import jsonable_encoder

from wiapi.models import WiapiResponse
from wiapi import wiapi

class WiapiHTTPException(HTTPException):
    pass

def wiapi_http_exception_handler(request: Request, e: HTTPException):
    return JSONResponse(
        status_code=e.status_code,
        content=jsonable_encoder(
            WiapiResponse(
                success=False,
                data={ 'message': e.detail }
            )
        )
    )

@wiapi.exception_handler(RequestValidationError)
async def wiapi_validation_exception_handler(request: Request, e: RequestValidationError):
    return JSONResponse(
        status_code=422,
        content=jsonable_encoder(
            WiapiResponse(
                success=False,
                data={ 'message': e.errors() }
            )
        )
    )

wiapi.add_exception_handler(WiapiHTTPException, wiapi_http_exception_handler)
