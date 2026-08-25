import os

from authforge import JWKSVerifier
from fastapi import Depends, FastAPI, Header, HTTPException

app = FastAPI()
verifier = JWKSVerifier(os.environ["AUTHFORGE_ISSUER"], os.environ["AUTHFORGE_AUDIENCE"])


def actor(authorization: str = Header()) -> dict[str, object]:
    if not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401)
    return verifier.verify(authorization.removeprefix("Bearer "))


@app.get("/protected")
async def protected(claims: dict[str, object] = Depends(actor)) -> dict[str, object]:
    return {"subject": claims["sub"]}
