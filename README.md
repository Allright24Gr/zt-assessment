# Readyz-T — Zero Trust 성숙도 진단 시스템

## 1. 처음 시작할 때 (최초 1회)

```powershell
npm i
```

---

## 2. 사이트 실행 (내 PC에서 보기)

```powershell
npm run dev
```

브라우저에서 **http://localhost:5173** 접속

---

## 3. 다른 사람에게 보여줄 때

### 같은 Wi-Fi 공유 (발표장, 회의실)

```powershell
npm run dev -- --host
```

터미널에 뜨는 `Network: http://192.168.x.x:5173` 주소를 상대방이 브라우저에 입력하면 접속됨.
단, 본인 PC와 **같은 Wi-Fi**여야 하고 서버가 켜져 있는 동안만 가능.

### 인터넷으로 공유 (Vercel 무료 배포)

```powershell
npm run build
```

빌드 후 [vercel.com](https://vercel.com) 에서 프로젝트 폴더 import → 자동 배포.
완료되면 `https://프로젝트명.vercel.app` 링크를 누구에게나 공유 가능.

---

## ⚠️ npm 실행 시 오류 날 때 (Windows PowerShell)

**오류 내용:** `스크립트를 실행할 수 없으므로 npm.ps1 파일을 로드할 수 없습니다`

**해결 (한 번만 하면 됨)** — PowerShell에 입력:

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

`Y` → 엔터 → 터미널 재시작 → 정상 실행
