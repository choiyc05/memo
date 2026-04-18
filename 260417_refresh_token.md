### 1. 리프레시 토큰의 작동 원리

1.  **로그인 성공 시:** 서버는 `Access Token`(30분 내외)과 `Refresh Token`(2주 내외) 두 개를 발급합니다.
2.  **Access Token 만료:** 프론트엔드가 요청을 보냈을 때 서버가 `401 Unauthorized`를 응답합니다.
3.  **토큰 갱신 요청:** 프론트엔드는 가지고 있던 `Refresh Token`을 서버의 `/refresh` 엔드포인트로 보냅니다.
4.  **검증 및 재발급:** 서버는 Redis에 저장된 값과 대조하여 `Refresh Token`이 유효하면 새로운 `Access Token`을 발급합니다.

---

### 2. 리프레시 토큰 구현 (FastAPI + Redis)

`uv add redis`가 되어 있다고 가정하고, 기존 UUID 방식에 리프레시 토큰 논리를 섞은 예시입니다.

```python
from datetime import datetime, timedelta
from jose import jwt
import redis
from app.core.config import settings

# Redis 연결 설정 (보통 의존성 주입으로 관리)
rd = redis.Redis(host='localhost', port=6373, db=0, decode_responses=True)

def create_tokens(user_id: str):
    # 1. Access Token 생성
    access_expire = datetime.utcnow() + timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = jwt.encode(
        {"sub": user_id, "exp": access_expire, "type": "access"}, 
        settings.JWT_SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )

    # 2. Refresh Token 생성
    refresh_expire = datetime.utcnow() + timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS)
    refresh_token = jwt.encode(
        {"sub": user_id, "exp": refresh_expire, "type": "refresh"}, 
        settings.JWT_SECRET_KEY, 
        algorithm=settings.ALGORITHM
    )

    # 3. Redis에 Refresh Token 저장 (UUID:Refresh_Token 또는 User_ID:Refresh_Token)
    # TTL(만료시간)을 설정하여 자동으로 Redis에서 삭제되게 함 (만료 처리 자동화)
    rd.setex(
        f"refresh_token:{user_id}", 
        timedelta(days=settings.REFRESH_TOKEN_EXPIRE_DAYS), 
        refresh_token
    )

    return {"access_token": access_token, "refresh_token": refresh_token}
```

---

### 3. 만료 처리 및 갱신 로직

프론트엔드에서 Access Token이 만료되어 `/token/refresh`를 호출했을 때의 서버 로직입니다.

```python
@app.post("/token/refresh")
async def refresh_access_token(refresh_token: str):
    try:
        # 1. JWT 서명 및 만료 체크
        payload = jwt.decode(refresh_token, settings.JWT_SECRET_KEY, algorithms=[settings.ALGORITHM])
        user_id = payload.get("sub")
        token_type = payload.get("type")

        if token_type != "refresh":
            raise HTTPException(status_code=401, detail="Invalid token type")

        # 2. Redis에 저장된 토큰과 일치하는지 확인 (보안 강화)
        saved_token = rd.get(f"refresh_token:{user_id}")
        if not saved_token or saved_token != refresh_token:
            raise HTTPException(status_code=401, detail="Refresh token expired or invalid")

        # 3. 새로운 Access Token 발급 (Refresh는 그대로 두거나 새로 갱신)
        new_access_token = create_access_token({"sub": user_id}) 
        return {"access_token": new_access_token}

    except JWTError:
        raise HTTPException(status_code=401, detail="Could not validate credentials")
```

---

### 💡 Broken Access Control 관점에서의 만료 처리

1.  **로그아웃 시 Redis 삭제:** 사용자가 로그아웃하면 Redis에서 해당 사용자의 `refresh_token:{user_id}` 키를 즉시 삭제하세요. 이렇게 하면 설령 공격자가 탈취한 토큰이더라도 더 이상 갱신이 불가능해집니다.
2.  **Access Token 블랙리스트:** 보안이 아주 중요하다면 로그아웃 시 남은 유효시간 동안의 Access Token을 Redis에 '블랙리스트'로 등록하여, 만료 전이라도 사용을 차단할 수 있습니다.
3.  **HTTP-Only Cookie:** 리프레시 토큰은 로컬 스토리지보다 `Http-Only` 쿠키에 담아 보내는 것이 XSS 공격으로부터 더 안전합니다.

---

### 1. 로그인할 때마다 새로 생성 (권장: RTR 방식)
이 방식을 **Refresh Token Rotation (RTR)**이라고 부릅니다. 로그인을 하거나 토큰을 갱신할 때마다 기존 리프레시 토큰은 무효화하고 새 토큰을 발급하는 방식입니다.

* **작동 방식:**
    1. 사용자가 아이디/비번으로 로그인합니다.
    2. 서버는 새로운 `Access Token`과 `Refresh Token`을 생성합니다.
    3. **기존에 Redis에 있던 해당 사용자의 리프레시 토큰을 새 토큰으로 덮어씁니다.**
* **장점:**
    * **보안성 최상:** 리프레시 토큰이 탈취당하더라도, 사용자가 다시 로그인하거나 토큰을 갱신하는 순간 탈취된 토큰은 쓸모가 없어집니다.
    * **동시 로그인 제어:** 자연스럽게 "가장 마지막에 로그인한 기기"만 세션을 유지하게 만들 수 있습니다.

---

### 2. 기존 토큰 재사용 (유효기간 내 유지)
이미 유효한 리프레시 토큰이 Redis에 있다면, 새로 로그인해도 그 토큰을 그대로 프론트에 전달하는 방식입니다.

* **작동 방식:**
    1. 로그인 시 Redis를 확인합니다.
    2. 기존 토큰의 만료 시간이 충분히 남았다면(예: 7일 이상) 그걸 그대로 줍니다.
* **단점:** 보안 사고가 났을 때 해당 토큰이 만료될 때까지 공격자가 계속 갱신을 시도할 수 있어 위험합니다.

---

### ⚠️ 주의할 점: 중복 로그인 허용 여부
만약 프로젝트가 **"여러 기기에서 동시에 로그인"**되는 것을 허용해야 한다면, Redis 키 설정을 조금 바꿔야 합니다.

* **기기 한 대만 허용:** `refresh_token:{user_id}` (로그인할 때마다 덮어쓰기)
* **여러 기기 허용:** `refresh_token:{user_id}:{device_id}` (기기별로 따로 저장)

---
