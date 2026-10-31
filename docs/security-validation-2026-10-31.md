# FileSharer 보안 수정·검증 기록

검증일: 2026-10-31 KST. 기준: `979ef5a2bc98ccfb7aa346d14042524ac74c691c` (작업 시작 시 GitHub main과 일치). 설치 프로그램 버전: 1.1.1.

| 항목 | 판정 | 근거 |
| --- | --- | --- |
| SEC-04 | 수정·검증 완료 | 개별 파일, 원본 파일, ZIP, 공유 페이지, HEAD, Range에 공통 만료·철회·PIN 검사를 적용하고 다운로드 승인 시 한도를 원자적으로 확인 |
| SEC-05 | 수정·검증 완료 | 무작위 256비트 서버 허가를 공유 객체·파일 경로·크기·수정 시각·암호화 형식·유효기간에 결합. Range 헤더만으로 한도 예외를 부여하지 않음 |
| DEP-03 | 수정·검증 완료 | Go 1.26.10으로 Windows 실제 설치 파일과 내장 tsproxy를 재빌드하고 내장 파일 해시/버전 확인. Linux 보조 프로그램도 빌드·검사 |
| Android | 적용 대상 아님 | 이 저장소에는 Android 프로젝트·네이티브 패키징 경로가 없음 |

## 수정 전과 후

실제 HTTP 처리 함수 `ProcessClient`를 루프백 TCP 연결로 호출하고 임시 파일만 사용했다.

| 입력 | 수정 전 | 수정 후 |
| --- | --- | --- |
| 만료된 폴더 개별 파일 GET | 200 + 시험 파일 본문 | 410, 파일 본문 없음 |
| 횟수 소진 후 개별 파일 GET | 200 + 시험 파일 본문 | 410 |
| 횟수 소진 후 원본 Range: bytes=0- | 206 + 전체 시험 본문 | 허가 없으면 410 |
| 승인받은 파일의 Range 재개 | 헤더 존재만으로 허용 | 유효한 허가·동일 파일 버전이면 206, 추가 차감 없음 |
| 정상 RevokeShare 후 접근 | 404 | 404 유지, 다른 공유는 정상 |

`CheckShareLocked`는 공유 존재, 만료·철회, PIN, 필요한 경우 한도를 검사한다. `AuthorizeDownload`는 전송 직전에 같은 공유 객체인지 재확인하고 같은 잠금 안에서 한도 예약과 허가 발급을 수행한다. 카운터 저장에 실패하면 예약과 허가를 취소하고 503을 반환한다. 저장 파일 쓰기도 같은 잠금으로 직렬화해 오래된 카운터가 나중에 덮어쓰이지 않게 했다.

폴더 개별 파일의 정규화와 경계 검사는 `ResolveSubfile`로 모았으며 junction/symlink 경로도 거절한다. `RevokeShare`의 store 제거, ZIP 정리, 해당 외부 터널 정리는 유지하고 그 공유의 재개 허가도 제거한다. 승인/거절 접속 기록을 유지한다.

## 다운로드 정책

- 새 GET 1건은 원본 파일 1개, 폴더 개별 파일 1개 또는 전체 ZIP 1건으로 계산한다. 같은 공유의 한도를 함께 사용한다. 전송 중단 시에도 이미 시작한 횟수는 환불하지 않는다.
- 허가 없는 최초 단일 Range도 새 다운로드로 승인·차감한다. 남은 한도가 없으면 거절한다. 처음 받은 허가를 이용해 나머지 구간을 받을 수 있다.
- HEAD는 파일 본문·새 허가·차감 없이 응답한다. 소진된 공유는 유효한 기존 허가가 없는 HEAD도 거절한다.
- 응답의 `X-Download-Token`과 대상별 HttpOnly 쿠키가 이어받기 증표다. 암호화 페이지는 토큰을 보관해 0바이트 수신 후 재시도에도 전송한다. 일반 브라우저의 Range 재개는 쿠키를 사용한다. 일반 GET은 기존 쿠키가 있어도 새 다운로드로 계산한다.
- 허가는 24시간 고정 유효기간을 가지며 공유 만료·해제가 우선한다. 파일 경로, 크기, UTC 수정 시각 또는 암호화 형식이 달라지면 기존 허가로 재개할 수 없다. Windows에서는 전송 중 쓰기·삭제를 허용하지 않는 읽기 핸들을 유지한다.
- 이미 승인된 HTTP 응답은 전송 중 공유가 만료·해제되어도 완료할 수 있다. 이후 시작되는 요청은 재개 허가가 있어도 거절한다.
- 하나의 Range 헤더에 여러 구간을 넣으면 416으로 거절한다. 승인된 토큰으로 별도 단일 구간을 병렬 요청하는 것은 허용하며 추가 차감하지 않는다.
- 허가는 프로세스 메모리에만 보관한다. 재시작 후에는 무효다. 유효 허가는 최대 4,096개를 보관하고 용량 부족 시 새 다운로드를 503으로 거절한다. 허가가 만료되면 새 승인 과정에서 정리한다.
- 허가는 bearer 증표다. 유효기간 안의 동일 다운로드 세션은 같은 구간을 재요청할 수 있다. 횟수 제한은 전달받은 바이트의 재복사를 금지하는 DRM이 아니다.

## 실행한 검증

| 환경 / 명령 | 실제 결과 |
| --- | --- |
| Windows .NET Framework 4.x / `powershell -File tests/run-security.ps1` | 146 assertions PASS |
| `node tests/browser-resume.cjs` | 0바이트 및 중간 끊김 후 암호화 페이지의 Range·허가 재전송 PASS |
| Windows / `powershell -File build.ps1` | tsproxy.exe, FileSharer.exe, FileSharer_Setup.exe 생성 성공 |
| Windows / `powershell -File tests/verify-package.ps1` | 설치 파일 → 앱 → 압축 보조 파일 해시 일치, 실제 Go 1.26.10 확인, 같은 크기의 구버전 캐시 교체 PASS |
| Windows amd64 / `GOTOOLCHAIN=go1.26.10 go test ./...` | 종료 0, `[no test files]` — Go 단위 테스트가 있는 것으로 집계하지 않음 |
| Linux amd64 / `GOTOOLCHAIN=go1.26.10 go test ./...` | 종료 0, `[no test files]` |
| Windows/Linux 각각 / `govulncheck -scan=symbol ./...` | 종료 0, 호출 심볼 0건·import 패키지 0건, 미사용 모듈 코드 경고 12건 |
| Linux amd64 / `go build -mod=readonly -trimpath ...` 및 `go version -m` | 빌드 성공, go1.26.10 |

HTTP 회귀에는 정상 PIN·잘못된 PIN, 실제 외부 파일에 대한 경로 탈출, 만료된 페이지/파일/ZIP/HEAD/Range, 허가 변조·다른 공유/개별 파일/변경된 ZIP·파일 버전 재사용, 허가 자체 만료, 실제 RevokeShare, 정상 ZIP 내용, 브라우저 쿠키 재개, 암호화 파일 복호화, 16개 동시 신규 요청(한도 3회), 16개 동시 승인 재개, 기존 DB 데이터 보존, 저장 실패 시 차감 취소가 포함된다.

회귀 도구는 TEMP/TMP와 SYSTEMTEMP를 모두 별도 폴더로 지정한다. SYSTEM 계정의 Windows는 SYSTEMTEMP를 우선하므로 TEMP/TMP만 지정했던 첫 패키지 검사에서 격리 경로 확인이 실패했다. 테스트 격리 설정을 수정한 뒤 해당 검사와 최종 HTTP 회귀를 다시 실행했다. 실패 실행을 성공으로 집계하지 않았다.

## 툴체인 및 생산 경로

공급자 [Go 릴리스 기록](https://go.dev/doc/devel/release)과 [GO-2026-6809](https://pkg.go.dev/vuln/GO-2026-6809)를 확인했다. 2026-10-31 기준 지원되는 수정 패치 중 기존 1.26 계열과 호환되는 **1.26.10**을 선택했다. [공식 대응 안내](https://go.dev/blog/emudhra-incident)는 Go 실행 파일의 재빌드와 `go version -m` 확인을 명시한다.

- `tsproxy/go.mod`: 최소 Go 1.26.10.
- `build.ps1`: `GOTOOLCHAIN=go1.26.10`, Windows amd64, CGO 비활성으로 생산 경로 고정. 빌드 결과 버전 검사 후 앱과 설치 파일에 내장한다. 호출자 환경변수는 복구한다.
- `.github/workflows/security.yml`: Windows HTTP/브라우저 로직 검사, Go 검사, 설치 파일 빌드·내장 파일 확인, Actions 산출물 보관을 추가했다. 이 문서의 실제 결과는 직접 실행한 검증이며 CI 실행 결과를 대신하지 않는다.
- 기존 추출 코드가 크기만 같으면 보조 프로그램을 재사용하던 부분은 SHA-256 비교로 변경했다. 실행 중인 구버전 파일을 덮어쓸 수 없으면 기존의 별도 임시 파일 실행 경로를 유지한다.

검증에 사용한 `govulncheck`는 v1.9.0이다. 전체 Windows 결과는 [windows-govulncheck.txt](validation-2026-10-31/windows-govulncheck.txt), Linux 결과는 [linux-govulncheck.txt](validation-2026-10-31/linux-govulncheck.txt)에 있다. 미사용 코드의 경고는 `golang.org/x/net`, `x/text`, `x/crypto`에 남는다. 현재 호출 경로에서 탐지되지 않았다는 결과이며, 의존성 전체에 결함이 없다는 뜻은 아니다.

## 기존 데이터와 산출물

`shares_db.txt`, PIN, 암호화 키, 설정 파일 형식은 변경하지 않았다. 기존 형식의 저장·재로드로 PIN·카운터·키 보존을 확인했다. 재개 허가는 업그레이드/프로세스 재시작을 넘겨 이전하지 않는다. 설치 프로그램 전체를 실제 사용 환경에 설치하거나 실행 중 앱을 교체하지 않았다.

최종 Windows 검증 빌드의 SHA-256:

| 파일 | SHA-256 |
| --- | --- |
| FileSharer.exe | `E18EC4C336810F43FFFA3499253FC115D4A616220E90A2160C11B4251E365367` |
| FileSharer_Setup.exe (1.1.1) | `F2048F8528AB5FB691BA964ACBF70FC9B9B2BAC35BF583542A0EF5CCE9038C34` |
| tsproxy.exe (Go 1.26.10) | `E75BBC4EB7B1D229FAFF82A39DD04E9AF3D3A80E193847EB62562C2A9D210718` |

빌드 환경·경로·타임스탬프에 따라 이후 재빌드의 C# 실행 파일 해시는 다를 수 있다.

## 제한 및 배포 상태

- 기존 C# 경고 CS0114 (`MainForm.InitLayout`) 1건이 남는다.
- 실제 Tailscale 계정 연결·외부 터널 개통, 브라우저 GUI 조작, 실사용 설치/업그레이드 마법사는 실행하지 않았다. 암호화 HTTP 본문과 브라우저 재시도 로직은 격리 검사로 확인했다.
- Host 기반 암호화 분기는 이번 SEC-04/05와 별도 검토 후보로 유지한다. 테스트의 localhost/외부 Host 구분 결과를 독립 보안 경계의 증명으로 취급하지 않는다.
- 소스·회귀 검사·빌드 스크립트 변경이다. main 병합, GitHub Release 발행, 운영 배포는 별도이며 이 문서가 이를 완료했다는 뜻은 아니다.
