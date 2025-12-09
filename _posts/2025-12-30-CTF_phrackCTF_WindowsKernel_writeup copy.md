---
layout: post
title:  "[phrack CTF 2025] Windows Kernel Challenge write-up"
date:   2025-12-30 21:00:20 +0900
categories: [ctf, Windows]
tags: [CTF, pwnable, Windows, Exploitation]
fullview: false
comments: true
#description: "pwn challenge i made last year and released on MSG CTF 2025"

---

지난 추석 기간 동안 풀어본 문제임
windwos 24h2 LFH의 바뀐 점과 그에 따른 non-paged pool LFH에서 릭하는 방법에 system권한을 얻는 과정까지 


## Screenshot {#screenshot}
<center><img src='/assets/CTF_phrackCTF_WindowsKernel_writeup/phrack_screenshot.png' width=auto height=auto></center>




##### Exploit code link {#exploit-code-link}
- [https://github.com/p05wn/Windows-CTF/tree/main/Phrack72_Binary_Exploitation_CTF_2025](https://github.com/p05wn/Windows-CTF/tree/main/Phrack72_Binary_Exploitation_CTF_2025)
