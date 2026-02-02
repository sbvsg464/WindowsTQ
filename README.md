
# WindowsPrivilegeEscalationVulnerabilityDisplayBox
**Language**: [English](#english) | [中文](#中文)

## English
Windows Privilege Escalation Vulnerability Display Box is a Windows security tool
designed to demonstrate and display privilege escalation vulnerabilities for
educational and research purposes.

## Overview
- Platform: Windows
- Type: Privilege Escalation Demonstration Tool
- Purpose: Security Research / Educational Use
- Language: C++

## Features
- Modify PowerShell execution policy
- Take ownership of files and directories as Administrator
- SYSTEM privilege escalation
- TrustedInstaller privilege escalation

## Planned Features
- UAC bypass to Administrator

## A disclaimer
> This project is intended for educational and security research purposes only.
> Any misuse or illegal use of this project is strictly prohibited.
> The author takes no responsibility for any consequences resulting from its use.

## Attention
Actually, there is a controversy. The privilege command refers to "trustedinstaller", but "whoami" returns "SYSTEM". So, I ultimately decided to grant "SYSTEM" privileges.

## 中文
## 什么是WindowsPrivilegeEscalationVulnerabilityDisplayBox
WindowsPrivilegeEscalationVulnerabilityDisplayBox是一个exe程序，为用户检测，演示Windows里面的提权漏洞<br>
相信我，WindowsPrivilegeEscalationVulnerabilityDisplayBox是用来演示的
## 提权漏洞是什么？
提权漏洞就是：<br>
系统、程序、服务、驱动里存在 bug   让攻击者 不该有高权限，却能拿到高权限<br>
关键点：<br>
不是“本来就有权限”，而是“不该有却拿到了”
## 目前已实现的功能：
- 更改powershell运行策略<br>
- 获取以administrator接管文件/文件夹的功能<br>
- 提权至SYSTEM<br>
- 提权至trustedinstaller
## 正在实现的功能：
- 不惊动UAC的情况下提权到Administrator
## 免责声明
> 本项目仅用于安全研究与漏洞演示，主要目的是帮助理解和预防相关安全问题。
> 请勿将其用于任何非法用途，使用者需自行承担由此产生的风险。
## 注意
实际上，有争议，提权命令说的是trustedinstaller，但是whoami却返回的是SYSTEM，所以，我最终决定为有SYSTEM权限
## 有自己的想法吗？
欢迎提交Issues!
## 发现BUG了吗？
欢迎提交Issues!
## 本项目遵守GPL v3开源协议
这个工具的初衷就是让提权简单化，易于演示。我也深知GitHub上也有比我研究的更彻底，更完美的人，他们有更好方案<br>
我也会努力学习滴~~~~
