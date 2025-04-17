# 🛡️ Netfilter Domain Blocker

> 특정 도메인을 HTTP 요청 수준에서 차단하는 Linux 기반 네트워크 필터 프로그램  
> `libnetfilter_queue`와 `iptables`를 활용해 실시간 도메인 필터링을 구현합니다.

---

## 📌 소개

이 프로그램은 Linux 시스템의 **Netfilter 프레임워크**를 기반으로 동작하며,  
**HTTP 요청의 `Host` 헤더를 파싱**하여 특정 도메인이 감지되면 해당 패킷을 **차단(DROP)** 합니다.

- 🔍 `iptables`로 NFQUEUE로 패킷 전달  
- 🧠 `libnetfilter_queue`로 패킷 분석  
- ✂️ 지정 도메인 포함 시 즉시 차단

---

## 🧰 사용법

### ✅ 1. 설치 (Ubuntu 기준)

```bash
sudo apt update
sudo apt install libnetfilter-queue-dev
