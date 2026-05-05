# Readyz-T - Zero Trust 성숙도 진단 시스템

## Windows 로컬에서 실행

PowerShell 또는 VS Code 터미널에서 실행합니다.

```powershell
git clone https://github.com/Allright24Gr/zt-assessment
cd zt-assessment
npm install
npm run dev
```

브라우저에서 접속:

```text
http://localhost:5173
```

## WSL Linux에서 실행

Ubuntu 같은 WSL 터미널에서 실행합니다.

```bash
git clone https://github.com/Allright24Gr/zt-assessment
cd zt-assessment
npm install
npm run dev
```

Windows 브라우저에서 접속:

```text
http://localhost:5173
```

WSL에서 실행했는데 Windows 브라우저 접속이 안 되면 아래처럼 host 옵션을 붙입니다.

```bash
npm run dev -- --host 0.0.0.0
```

그 다음 다시 접속:

```text
http://localhost:5173
```

## Docker로 실행

Docker Desktop이 설치되어 있으면 아래 명령어로 실행할 수 있습니다.

```powershell
docker compose up --build
```

브라우저에서 접속:

```text
http://localhost:8080
```

종료:

```powershell
docker compose down
```

## 같은 네트워크에서 다른 사람에게 보여주기

개발 서버를 외부 접속 가능하게 실행합니다.

Windows PowerShell:

```powershell
npm run dev -- --host 0.0.0.0
```

WSL Linux:

```bash
npm run dev -- --host 0.0.0.0
```

터미널에 표시되는 `Network` 주소를 같은 Wi-Fi에 있는 사람에게 공유합니다.

```text
예: http://192.168.0.15:5173
```

학교/공용 Wi-Fi에서는 기기 간 접속이 막힐 수 있습니다. 이 경우 Vercel, localtunnel, ngrok 같은 공개 링크 방식이 필요합니다.

## 빌드 확인

```powershell
npm run build
```

WSL에서는 같은 명령을 bash에서 실행하면 됩니다.

```bash
npm run build
```

## PowerShell 실행 정책 오류

Windows PowerShell에서 아래 오류가 나면:

```text
스크립트를 실행할 수 없으므로 npm.ps1 파일을 로드할 수 없습니다
```

PowerShell에서 한 번만 실행합니다.

```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned
```

`Y`를 입력한 뒤 터미널을 다시 열고 실행합니다.
