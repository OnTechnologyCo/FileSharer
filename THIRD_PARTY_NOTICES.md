# Third-party dependencies / 외부 의존성

`tsproxy` uses `tailscale.com` **v1.102.3**, as declared in `tsproxy/go.mod`.

The Tailscale module's BSD 3-Clause license is reproduced in [third_party/tailscale.LICENSE](third_party/tailscale.LICENSE). Its transitive dependencies are listed in `tsproxy/go.mod` and `tsproxy/go.sum` and retain their own copyright notices and licenses. Dependency source code and compiled binaries are not bundled in this repository.

When distributing a compiled helper, application, or installer, include the notices and licenses required by the exact dependencies in that build. The single Tailscale license included here is not a complete notice bundle for every transitive dependency.

`tsproxy`는 `tsproxy/go.mod`에 선언된 `tailscale.com` **v1.102.3**을 사용합니다. 해당 모듈의 BSD 3-Clause 라이선스 원문은 위 파일에 포함합니다. 간접 의존성에는 각각의 저작권과 라이선스가 적용됩니다. 이 저장소에는 의존성 소스나 컴파일된 실행 파일을 포함하지 않습니다.

실행 파일이나 설치 프로그램을 배포할 때는 실제 빌드에 포함된 의존성의 필수 고지와 라이선스를 함께 제공해야 합니다. 이 문서에 연결한 Tailscale 라이선스만으로 모든 간접 의존성의 고지를 대신하지 않습니다.
