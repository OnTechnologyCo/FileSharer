# FileSharer

[한국어](README.md) | [English](README.en.md)

Windows에서 파일과 폴더를 링크로 공유하는 C# Windows Forms 프로그램입니다. 로컬 네트워크에서 사용할 수 있으며, SSH 릴레이 또는 Tailscale Funnel을 이용한 외부 공유 기능도 포함합니다.

## 주요 기능

- 파일·폴더 공유와 브라우저 다운로드
- 공유 링크, QR 코드, 폴더 탐색 및 ZIP 다운로드
- PIN, 만료 시간, 다운로드 횟수 제한 및 공유 해제
- 공유 관리 화면과 접속 기록
- Tailscale `tsnet` 기반 외부 공유용 Go 보조 프로그램

## 소스 구성

| 파일 | 역할 |
| --- | --- |
| `FileSharer.cs` | Windows Forms 화면, HTTP 서버, 공유 관리 및 외부 연결 |
| `Setup.cs` | Windows 설치 프로그램 |
| `tsproxy/main.go` | Tailscale Funnel과 로컬 HTTP 서버를 연결하는 보조 프로그램 |
| `tsproxy/go.mod`, `tsproxy/go.sum` | Go 의존성 및 무결성 정보 |
| `filesharer.ico`, `filesharer_128.png` | 프로그램 아이콘 |
| `build.ps1` | 보조 프로그램, 본 프로그램, 설치 프로그램 빌드 |

## 빌드

Windows의 .NET Framework 4.x C# 컴파일러와 Go가 필요합니다. `tsproxy/go.mod`에 선언된 Go 버전은 **1.26.6**입니다. Go의 도구 체인 자동 선택이 활성화되어 있으면 필요한 버전을 다운로드할 수 있습니다. 처음 빌드할 때는 Go 도구 체인과 의존성 다운로드를 위한 인터넷 연결이 필요할 수 있습니다.

프로젝트 폴더에서 PowerShell을 열고 실행합니다.

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\build.ps1
```

결과는 `dist/`에 생성됩니다. `FileSharer.exe`에는 압축한 Go 보조 프로그램이 포함되며, `FileSharer_Setup.exe`에는 본 프로그램과 아이콘이 포함됩니다. 직접 실행하거나 설치 프로그램으로 설치할 수 있습니다. 기존 루트 폴더의 실행 파일과 실제 설정은 빌드 결과로 덮어쓰지 않습니다.

## 사용

1. 프로그램을 실행하고 사용할 IP 주소와 포트를 선택합니다. 기본 포트는 `3000`입니다.
2. 공유할 파일 또는 폴더를 추가하고 필요한 PIN, 만료 시간, 다운로드 제한을 지정합니다.
3. 링크 또는 QR 코드를 전달합니다. 로컬 공유는 서버 PC에 접속할 수 있는 네트워크에서 사용합니다.
4. 외부 공유를 사용할 경우 선택한 연결 방식에 필요한 설정을 입력합니다. Tailscale 방식에는 유효한 인증 키와 계정의 Funnel 사용 설정이 필요합니다.

외부 공유를 켜면 공유 주소에 인터넷에서 접근할 수 있습니다. 공유 대상과 접근 설정을 확인하고, 사용을 마친 링크는 해제하세요. 인증 키와 실제 접속 기록은 저장소에 올리지 마세요.

## 공개 저장소 범위

이 저장소에는 소스, 아이콘, 빌드 스크립트와 문서만 포함합니다. 실행 파일, 설치 파일, 실제 설정, 공유 목록, 접속 로그, 터널 상태, 첨부 파일, 중복 백업과 과거 작업 메모는 제외합니다. 로컬의 기존 파일은 유지합니다.

## 라이선스 및 의존성

현재 프로젝트 자체에 별도의 오픈 소스 라이선스를 지정하지 않았습니다. 재배포·수정·상업적 이용을 위한 허락은 저장소 소유자에게 문의하세요. Go 의존성에는 각 패키지의 라이선스가 적용됩니다. [의존성 안내](THIRD_PARTY_NOTICES.md)와 [Tailscale 라이선스](third_party/tailscale.LICENSE)를 참고하세요.
