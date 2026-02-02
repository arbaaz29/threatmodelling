# Security Solution for Healthcare Infrastructure

## Team Members:

### Arbaaz Jamadar 

### Srinivasan Anandan 

### Mitraj Parmar 


## Table of contents

1. Overview
2. Objective
3. Cybersecurity Incident Analysis
4. Security Improvement Plan Methodology
5. Potential Threats and Their Implications
6. Current Network Architecture
7. STRIDE Model
8. DREAD Model
9. Prioritizing the risks
10. Security Solutions/Recommendations
11. Products and Features
12. Security Model
13. Improved Infrastructure
14. Cost Estimation
15. References


## 1. Overview

Our healthcare system's IT infrastructure recently experienced a severe breach, resulting in the compromise of several computers within our network. This breach has inflicted significant damage, particularly within our Linux network environment, which houses

critical research data vital to our organization, as well as sensitive information such as

patients' PII and health-related data. Initial access was achieved by exploiting a command

injection vulnerability in our web server which hosts our website, that is utilized by patients,

doctors, and customer support to interact with the healthcare system digitally. Leveraging

this foothold, the attacker detected a private Windows network connected to the DMZ and

successfully pivoted into the Windows environment. Exploiting misconfigured network

devices, such as insecure firewall rules or improperly configured VPN gateways,

unauthorized access was gained to multiple systems within the network. Upon infiltrating

the Windows network, thorough reconnaissance revealed the presence of Samba services

on a domain controller, hinting at a separate Linux network. Subsequent investigation

unveiled communication between the Windows domain controller's Samba service and IP

addresses outside the local subnet, indicating the existence of the Linux network.

Capitalizing on this revelation, the attacker exploited a host-based vulnerability on a

Windows server to elevate privileges and breach the Linux network. Once inside, further

exploitation of vulnerabilities ensued, resulting in escalated privileges and persistent
access, facilitating data exfiltration and malicious activity within the Linux environment.

This breach not only inflicted significant financial losses but also tarnished our

organization's reputation due to the prolonged undetected presence of the attackers within

our network for over two months. As a result, our company's leadership has prioritized the

enhancement of our IT security posture, necessitating urgent action while mindful of

budgetary constraints. The primary objective is to preemptively detect and mitigate

security threats before they penetrate our network, thereby averting substantial losses.

Furthermore, addressing potential data leakage vulnerabilities is imperative to fortify our


defensive security posture. As consultants tasked with evaluating and proposing a

solution, our aim is to bolster the organization's security defenses, prevent future cyber

attacks, and expedite detection in the event of a successful breach.

To accomplish this goal, we are entrusted with implementing defensive strategies to

combat security threats. The allocated budget of $500,000 will cover the acquisition of

necessary hardware and software, along with the recruitment of two full-time security

administrators for the initial year. Our proposed solution will encompass a comprehensive

array of security measures tailored to mitigate vulnerabilities and enhance threat detection

capabilities across both our Linux and Windows networks. Through meticulous planning

and strategic deployment of resources, we aim to fortify our organization's security

posture, safeguard critical data assets, and safeguard against future cyber threats.

## 2. Objective

Our healthcare system’s security objectives are paramount in safeguarding our assets and ensuring
operational continuity. Prioritizing these objectives aligns with our core business operations and
enables the effective allocation of resources to address critical security concerns.

1. **Protecting Intellectual Property and Research Data** : Safeguarding the integrity and
    confidentiality of research data, patients' health-related data, personally identifiable
    information (PII), and intellectual property stored within the Linux network.

```
Prioritization : Given that our organization relies heavily on research data for scientific
advancements and medical development, as well as patient data, protecting intellectual
property should be a top priority. This is particularly crucial in the context of a research-
focused company where proprietary information is a key asset.
```
2. **Maintaining Operational Continuity** : Ensuring uninterrupted business operations and
    availability of critical systems and services, including the web server used for seamless
    interaction between patient, doctors and customer support.


```
Prioritization : Operational continuity is vital for sustaining revenue streams and customer
satisfaction, making it a high-priority objective.
```
**3. Protecting Customer Data and Trust** : Safeguarding patients' data stored on the web server
    and database server, as well as ensuring compliance with privacy regulations, are essential
    for maintaining customer trust.

```
Prioritization : In the healthcare sector, adherence to the Health Insurance Portability and
Accountability Act (HIPAA) is crucial. HIPAA sets strict standards for the protection of
patients' sensitive health information, mandating measures such as encryption, access
controls, and regular audits to ensure data security. Compliance with HIPAA not only
safeguards patients' privacy but also fosters trust between healthcare providers and their
clientele.
```
4. **Enabling Secure Remote Work:Objective** : Ensuring the security of remote work
    environments, including laptops issued to employees, to facilitate increased work-from-
    home capabilities.

```
Prioritization : With a significant portion of personnel working remotely, securing remote
access and endpoints becomes critical to prevent unauthorized access and data breaches.
```
By aligning the proposed security objectives with the company's core business operations and
priorities, we can develop a comprehensive security solution that effectively mitigates risks and
protects critical assets while supporting the organization's strategic goals.


## 3. Cybersecurity Incident Analysis..........................................................................

Our healthcare organization recently experienced attacks that can be primarily classified into two
types: ransomware attacks, which are among the most common threats to healthcare systems,
and data breaches. At the time of these attacks, the following measures were implemented to
prevent such incidents:

1. **Firewalls and Intrusion Detection/Prevention Systems (IDS/IPS):** A single set of firewall
    and IDS/IPS system is implemented at network boundaries between the DMZ, internet, and
    private networks to monitor and filter incoming and outgoing traffic, thereby preventing
    unauthorized access and detecting suspicious activity effectively.
2. **Antivirus and Antimalware Software:** Endpoint protection software, such as antivirus and
    antimalware tools, has been installed on every device within the healthcare system. This
    software is instrumental in detecting and removing malicious software, including
    ransomware, from individual devices such as desktops and servers.
3. **Data Encryption** : Given the sensitive nature of the data within our healthcare system,
    including Personally Identifiable Information (PII) of patients, robust encryption measures
    have been employed. Data is encrypted both in transit and at rest to safeguard it from
    unauthorized access in the event of a breach. Transport Layer Security (TLS/SSL) protocols
    are utilized for protecting data in transit, while Data Encryption Standard (DES) is
    implemented to encrypt data at rest.
4. **Employee Training and Awareness** : A comprehensive security awareness training program
    has been implemented to educate all personnel about cybersecurity best practices. This
    initiative equips employees with the knowledge to recognize phishing attempts and other
    social engineering tactics commonly used in ransomware attacks, thereby bolstering the
    organization's overall security posture.
5. **Access Control and Least Privilege Principle:** Adhering to the principle of least privilege,
    access to sensitive systems and data is strictly controlled within our organization. Access


```
privileges are granted only to authorized personnel on a need-to-know basis, effectively
reducing the risk of unauthorized access and potential data breaches.
```
Despite having implemented all the measures aimed at preventing ransomware attacks and data
breaches within our healthcare infrastructure, a significant security incident occurred. Upon
conducting a thorough investigation post-attack, it became evident that several gaps existed due to
lax enforcement of policies and inadequate monitoring. These gaps are outlined as follows:

1. **Insufficient User Training:** Although cybersecurity training programs were available, not all
    employees took them seriously or received adequate training. Consequently, an employee
    fell victim to a phishing email containing ransomware, which managed to bypass the
    antivirus software.
2. **Insufficient Monitoring and Detection:** One significant gap in the healthcare infrastructure
    lies in its reliance on a single set of firewall and IDS/IPS systems. This configuration creates
    a bottleneck in traffic inspection and reduces monitoring effectiveness, thereby increasing
    the risk of attackers evading detection and exploiting vulnerabilities. To address this issue,
    implementing a defense-in-depth approach with segmented networks and multiple security
    layers can enhance monitoring and detection capabilities, ultimately reducing the
    likelihood of successful ransomware attacks and data breaches.
3. **Inadequate Endpoint Security:** Inadequate patch management allowed vulnerabilities
    within the system to remain unaddressed, providing attackers with entry points into the
    infrastructure. This failure stemmed from gaps in the patch management process, including
    delays in applying critical security patches and ineffective prioritization of patching efforts.
4. **Weak Access Controls and Data Encryption:** Weak access controls and data encryption
    were significant vulnerabilities in the healthcare infrastructure. Access controls were lax,
    allowing the ransomware to laterally traverse the network, compromising sensitive data on
    both Windows administration and Linux research machines. Moreover, data confidentiality
    and integrity during transit relied solely on SSL/TLS version 1.1, which is plagued with
    vulnerabilities. To safeguard data at rest, the infrastructure employed the DES algorithm,


```
which is considered insufficiently robust. As a result, compliance with HIPAA regulations
was compromised, leading to potential legal consequences.
```
5. **Inadequate Incident Response Planning:** The organization lacked a robust incident
    response plan for promptly detecting, containing, and mitigating security incidents.
    Additionally, there were gaps in communication and coordination among stakeholders
    during incident response efforts, resulting in delays in identifying and responding to the
    breach.
6. **Lack of Backup Strategy:** Despite regular backups, their storage lacked offsite security
    (employing DES encryption for data at rest) and reliability testing. Consequently, the
    restoration process became protracted and uncertain, exacerbating the ransomware
    attack's impact.

While the healthcare infrastructure has implemented basic measures to prevent ransomware
attacks and data breaches, several gaps and failures contributed to the successful breach.
Addressing these issues necessitates a comprehensive approach, encompassing the
enhancement of monitoring and detection capabilities, improvement of endpoint security,
prioritization of patch management, reinforcement of user awareness training, and
development of a robust incident response plan.

## 4. Security Improvement Plan Methodology

**1. Gap Analysis and Prioritization** : Conduct a comprehensive gap analysis to identify all
    vulnerabilities and weaknesses in the current security posture. Prioritize these gaps based
    on their severity and potential impact on the organization's operations and data security.
**2. Enhanced User Training and Awareness** : Develop and implement an enhanced
    cybersecurity training program for all employees, emphasizing the importance of vigilance
    against phishing attempts and other social engineering tactics. Regular phishing
    simulations should be conducted to test and reinforce employees' awareness and response
    to potential threats.


**3. Segmented Network Architecture** : Implement a segmented network architecture with
    separate zones for the DMZ, Windows administration network, Linux research network, and
    VPN-connected remote users. Deploy dedicated firewalls and intrusion
    detection/prevention systems for each zone to enhance monitoring and detection
    capabilities and minimize the risk of lateral movement by attackers.
**4. Endpoint Security Enhancement** : Strengthen endpoint security by improving patch
    management processes to ensure timely application of security patches and updates.
    Deploy advanced endpoint protection solutions capable of detecting and blocking
    sophisticated malware, including ransomware. Implement endpoint detection and
    response (EDR) solutions to proactively detect and respond to suspicious activity on
    endpoints.
**5. Access Control and Data Encryption** : Enforce strict access controls based on the
    principle of least privilege to limit users' access to sensitive systems and data. Implement
    robust data encryption protocols, such as Advanced Encryption Standard (AES), for data at
    rest and in transit to ensure confidentiality and integrity.
**6. Incident Response Plan Development:** Develop and implement a comprehensive incident
    response plan outlining procedures for detecting, containing, and mitigating security
    incidents. Define roles and responsibilities for incident response team members and
    establish communication channels for timely coordination and decision-making during
    security incidents.
**7. Backup and Recovery Strategy** : Enhance the backup and recovery strategy by
    implementing offsite storage solutions with robust encryption to safeguard backups from
    ransomware attacks. Regularly test backup integrity and reliability to ensure prompt and
    successful recovery in the event of a security incident.
**8. Continuous Monitoring and Improvement** : Implement continuous monitoring
    mechanisms to detect and respond to security threats in real-time. Conduct regular


```
security audits and assessments to evaluate the effectiveness of security controls and
identify areas for further improvement.
```
**9. Employee Engagement and Accountability:** Foster a culture of cybersecurity awareness
    and accountability among employees by promoting active participation in security
    initiatives and encouraging reporting of suspicious activities. Recognize and reward
    employees for their contributions to maintaining a secure environment.
**10. Regular Training and Review:** Conduct regular training sessions and security awareness
    programs to keep employees updated on emerging threats and best practices. Review and
    update security policies, procedures, and controls periodically to adapt to the evolving
    cybersecurity landscape and regulatory requirements.

By implementing this methodology, the healthcare organization can address and improve its
security posture, mitigating the risk of future cybersecurity incidents and ensuring the
confidentiality, integrity, and availability of sensitive data and critical systems.

## 5. Potential Threats and Their Implications

**1. Ransomware Attacks** : Ransomware poses a significant threat to healthcare organizations,
    encrypting critical data and systems and demanding ransom payments for decryption keys.
    Such attacks can disrupt healthcare services, compromise patient care, and result in
    financial losses and reputational damage.
**2. Data Breaches** : Data breaches can occur due to various factors, including unauthorized
    access to sensitive patient information, inadequate security controls, and insider threats.
    Breached patient data can be exploited for identity theft, financial fraud, or other malicious
    purposes, leading to legal liabilities, regulatory penalties, and damage to the organization's
    reputation.


**3. Phishing and Social Engineering:** Phishing emails and social engineering tactics are
    commonly used by attackers to trick employees into disclosing sensitive information or
    downloading malware onto their devices. Successful phishing attacks can compromise
    user credentials, facilitate unauthorized access to network resources, and serve as entry
    points for ransomware and other malware.
**4. Insider Threats** : Insiders, including employees, contractors, or partners with access to
    sensitive data and systems, can pose a significant threat to healthcare organizations.
    Insider threats may involve malicious actions, such as unauthorized data access or
    exfiltration, or inadvertent behaviors, such as negligence or unintentional data disclosure,
    resulting in data breaches and operational disruptions.
**5. Exploitation of Vulnerabilities** : Exploiting vulnerabilities in software, applications, or
    network infrastructure is a common tactic used by cybercriminals to gain unauthorized
    access to healthcare systems. Failure to promptly patch known vulnerabilities can leave
    systems and devices susceptible to exploitation, leading to data breaches, system
    compromise, and potential disruption of healthcare services.
**6. Denial of Service (DoS) Attacks** : DoS attacks aim to disrupt the availability of healthcare
    services by flooding network resources, servers, or applications with excessive traffic,
    rendering them inaccessible to legitimate users. Such attacks can result in downtime,
    service interruptions, and loss of patient trust and confidence in the organization's ability to
    deliver timely care.
**7. Malware Infections** : Malware infections, including viruses, Trojans, and spyware, can
    compromise the integrity and confidentiality of healthcare data, disrupt critical systems
    and operations, and facilitate unauthorized access by attackers. Malware may be
    distributed through malicious websites, email attachments, or removable storage devices,
    posing a constant threat to healthcare organizations' IT infrastructure.
**8. Unauthorized Access and Privilege Escalation** : Unauthorized access to sensitive systems
    and data, coupled with privilege escalation, can enable attackers to gain extensive control


```
over healthcare networks and resources. Attackers may exploit weak access controls,
stolen credentials, or misconfigured permissions to escalate privileges and move laterally
within the network, increasing the risk of data breaches and system compromise.
```
## 6. Current Network Architecture

1. DMZ (Demilitarized Zone):
    a. Contains the web server hosting the web portal accessible to patients, doctors,
       and customer support.
    b. Provides a buffer between the internal network and external internet traffic.
2. Windows Network:
    a. Manages the entire IT infrastructure of the healthcare system.
    b. Responsible for access control and authentication for patients and customers.
    c. Connected to both the Linux network and DMZ to manage and update both
       networks.
3. Linux Network:
    a. Stores crucial data related to patients and research work.
    b. Most doctors operate through this network.
    c. Acts as the data server of the IT infrastructure.
4. VPN Connection:
    a. Facilitates secure connections for employees working remotely.
    b. Provides a secure tunnel for remote access to the internal network resources.
    c. Ensures confidentiality and integrity of data transmitted over the internet.
5. Web Application Firewall (WAF):
    a. Implements a layer of defense against web-based attacks.
    b. Filters and monitors HTTP traffic to and from the web server.
    c. Detects and blocks malicious activity, such as SQL injection and cross-site
       scripting (XSS) attacks.


6. Network Segmentation:
    a. Divides the network into smaller segments or zones.
    b. Isolates critical systems and sensitive data from the rest of the network.
    c. Limits the scope of a breach and prevents lateral movement by attackers.
7. Access Controls and Authentication Mechanisms:
    a. Enforces strict access controls to ensure that only authorized users can access
       sensitive resources.
    b. Implements robust authentication mechanisms, such as multi-factor
       authentication (MFA) or biometric authentication.
    c. Validates user identities and authorizes access based on predefined
       permissions and roles.
8. Encryption of Sensitive Data:
    a. Protects confidential information by encrypting it at rest and in transit.
    b. Secures data stored on servers or databases by encrypting it using
       cryptographic algorithms.
    c. Safeguards data transmitted over the network by encrypting communication
       channels with protocols like SSL/TLS.


## Current Architecture:


## HIPAA Compliance:

```
HIPAA (Health Insurance Portability and Accountability Act) is a federal law that sets standards
for protecting the privacy and security of individuals' protected health information (PHI). HIPAA
cybersecurity compliance is essential for any organization that deals with PHI, such as
healthcare providers, health plans, and healthcare clearinghouses.
Here are some key aspects of HIPAA cybersecurity compliance:
```
1. **Risk Analysis and Risk Management:** Organizations must conduct a thorough risk
    analysis to identify potential threats and vulnerabilities to the confidentiality, integrity,
    and availability of protected health information (PHI). Based on the risk analysis, they
    must implement appropriate risk management measures to mitigate identified risks.
2. **Access Controls:** HIPAA requires implementing technical and physical safeguards to
    limit access to PHI to only authorized individuals and processes. This includes
    measures such as unique user identification, emergency access procedures, and
    automatic logoff mechanisms.
3. **Audit Controls:** Organizations must implement hardware, software, and/or procedural
    mechanisms to record and examine activity in information systems that contain or use
    PHI.
4. **Integrity Controls:** These controls are designed to protect PHI from improper alteration
    or destruction. They include measures such as electronic mechanisms to corroborate
    data integrity and procedures to verify that PHI has not been altered or destroyed in an
    unauthorized manner.
5. **Transmission Security:** HIPAA requires implementing technical security measures to
    guard against unauthorized access to PHI transmitted over electronic communications
    networks.
6. **Contingency Planning:** Organizations must establish policies and procedures for
    responding to emergencies or other occurrences that could damage systems
    containing PHI. This includes data backup plans, disaster recovery plans, and
    emergency mode operation plans.
7. **Workforce Training and Management** : HIPAA requires providing appropriate training to
    workforce members on policies and procedures related to PHI security, as well as


```
applying appropriate sanctions against workforce members who violate these policies
and procedures.
```
8. **Regular Security Evaluations:** Organizations must periodically evaluate their security
    measures to ensure they continue to provide adequate protection.

Achieving and maintaining HIPAA cybersecurity compliance is an ongoing process that requires
organizations to continuously assess and address potential risks to the confidentiality, integrity,
and availability of PHI. To achieve HIPAA compliance, the organization needs to address these
identified gaps and implement the necessary technical, administrative, and physical
safeguards required by the HIPAA Security Rule and Privacy Rule.

**1. Inadequate Access Controls and Data Encryption:**
    a. Weak access controls and data encryption were significant vulnerabilities in the
       healthcare infrastructure. Specifically:
          i. Access controls were lax, allowing the ransomware to laterally move
             across the network and compromise sensitive data on both Windows
             administration and Linux research machines.
ii. Data in transit relied solely on the outdated and insecure SSL/TLS 1.
protocol for encryption.
iii. Data at rest was encrypted using the DES algorithm, which is considered
insufficiently robust and no longer meets HIPAA standards.
**2. Lack of Comprehensive Risk Assessments and Risk Management:**
    a. There is no mention of regular risk assessments or risk management plans being
       conducted to identify and mitigate potential vulnerabilities related to the
       storage, transmission, and handling of protected health information (PHI).
       Failure to assess and address risks can lead to HIPAA compliance gaps.
**3. Insufficient Auditing and Monitoring:**
    a. The organization relied on a single set of firewall and IDS/IPS systems, which
       created a bottleneck in traffic inspection and reduced monitoring effectiveness.
       Inadequate monitoring and auditing of access to PHI can lead to HIPAA
       violations going undetected.


**4. Gaps in Employee Training and Awareness:**
    a. While the organization had a security awareness training program, not all
       employees took it seriously or received adequate training. Lack of proper
       employee training best practices for handling PHI can lead to compliance
       violations.
**5. Inadequate Incident Response and Disaster Recovery Planning:**
    a. The organization lacked a robust incident response plan for promptly detecting,
       containing, and mitigating security incidents. Additionally, there were gaps in
       communication and coordination during incident response efforts. Failure to
       have proper incident response and disaster recovery plans in place can lead to
       HIPAA violations in the event of a data breach or system failure.

As per the gaps found and categorized we have prioritized risks and developed a plan to address
implement proper security procedures and measures.

## 7. STRIDE Model

## Threat Property Violeted Threat Definition

```
Spoofing Authentication 1. Attackers could spoof
identities to gain
unauthorized access
to systems and data
(e.g., spoofing doctor
or patient identities)
```
2. Spoofing of IP
    addresses to bypass
    access controls
3. Spoofing of HTTPS
    certificates for man-in-
    the-middle attacks


```
Tampering Integrity 1. Tampering with data in
transit (e.g., modifying
patient records,
prescriptions)
```
2. Tampering with
    configuration files or
    system logs
3. Tampering with
    software updates or
    security patches
**Repudiation Non-repudiation** 1. Users denying their
actions or activities on
the systems
2. Lack of auditing or
    insufficient audit logs
3. Inability to prove data
    integrity or origin
**Information Disclosure Confidentiality** 1. Disclosure of sensitive
patient data (PHI) due
to data breaches
2. Disclosure of
    intellectual property or
    research data
3. Inadvertent disclosure
    by insiders (e.g.,
    misconfigured
    permissions)
4. Insider threats (e.g.,
    disgruntled
    employees, contractor
    misconduct)


```
Denial of Service Availability 1. DoS attacks on web
servers or network
infrastructure
```
2. Distributed DoS
    (DDoS) attacks on
    critical systems
3. Malware infections
    (e.g., ransomware,
    trojans)
4. Physical security
    threats (e.g., theft,
    unauthorized access
    to facilities)
**Elevation of privilege Authorization** 1. Exploiting software
vulnerabilities for
privilege escalation
2. Insecure
    configurations leading
    to unauthorized
    elevated access
3. Unauthorized lateral
    movement within the
    network


## 8. DREAD Model

The measuring scale will be 1(low),2 (intermediate), 3(High).

```
Threat D R E A D Total
Data Breaches 3 2 2 3 1 11
Malware
Infections
```
### 3 3 2 3 1 13

```
Exploiting
Code Flaw
```
### 3 2 2 3 2 12

```
Database
vulnerabilities
```
### 3 1 1 3 1 9

```
Phishing/Social
Engineering
```
### 3 3 3 3 3 15

```
Software
Vulnerabilities
```
### 1 1 1 1 1 5

```
Denial of
Service
```
### 1 3 2 3 1 10

```
Weak
Credentials
```
### 2 1 1 1 1 6

```
Physical
Access
```
### 3 1 1 3 1 9

```
Malicious
Insider
```
### 2 2 1 3 1 9


## 9. Prioritizing the risks

As per the observations we have created a list of risks and their priorities, the priority list is as
follows:

1. **Securing Webservers:** These servers hold sensitive information like usernames and
    passwords that can help an attacker gain access to
       a. **Command injection:** The attacker was able to gain access to network by exploiting
          the command injection vulnerability on the website. They used this vulnerability to
          create a payload which created a reverse shell on the server that hosted the website
          and then used other TTPs to find persistence on the machine.
       b. **Information Disclosure:** Absesnce of Web application firewall (WAF) can cause
          information disclosure. This vulnerability allows attackers to obtain sensitive
          information like usernames and passwords.
       c. **SQL injection:** The website trusts user input, the website queries the database to
          retrieve product details and user details. If the user input is trusted and no
          sanitization measures are applied to it. It is possible to obtain a motherload of
          information from SQL injection attacks.
**2. Firewall:**
    a. The implemented firewalls function solely as packet filtering mechanisms,
       characterized by their static evaluation of inbound packets against predefined
       criteria, including permitted IP addresses, packet attributes such as type and port
       number, and other elements of the packet protocol headers. This method entails
       the omission of packet routing functionality; instead, packets are scrutinized
       individually, and those failing to meet the established criteria are summarily
       discarded, thereby terminating their transmission without further processing. It
       filters traffic based on MAC addresses and has no visibility of higher-level protocols,
       it is easy to bypasss these kind of firewall by using high-level protocols. It can also
       be bypassed by MAC spoofing. These firewalls are widely implemented because of
       low computation and extremely fast and efficient for scanning traffic.
    b. **Inefficient Scalability** :
       i. The management of a sophisticated network, characterized by a diverse
          array of high-level and low-level protocols facilitating numerous requests


```
and packet transmissions, poses significant challenges for a layer 2 firewall.
Moreover, the dynamic nature of network traffic necessitates real-time rule
implementation, a task hindered by the inherent limitations of firewalls. To
effectively mitigate online threats, a holistic approach is imperative, wherein
layer 2 firewalls are supplemented with complementary security measures
to provide comprehensive protection.
```
**3. Proper implementation of IDS and IPS:**
    A network that lacks proper implementation of an intrusion detection system (IDS)
    and intrusion prevention system (IPS) is susceptible to several cyber dangers, such
    as:
a. Unauthorized access: IDS can detect and alert about unauthorized access, but
intrusion prevention detects and tries to prevent unauthorized access. IDS can be
integrated easily while IPS needs some time to install and need to be maintained
periodically.
b. Malware and Ransomware: An IDS and IPS that works on a network layer can
analyze packets and identify patterns in networking that may be suspicious and may
in case of IDS alert and in case of IPS alert and prevent any malicious activity.
Ransomware and malware usually communicate with C2 servers, and for one time
deployment of malwares and ransomwares a Host based IDS and Host based IPS
can be more effective.
c. Insider Threat: as IDS and IPS analyze logs and user behavior patterns, they can
establish patterns between unauthorized access request or access requests to
resources they don’t have access to this can help delve deeper into whether the
accounts were compromised or whether there was a insider who was trying to gain
access to restricted resources.
d. DDoS: as IDS and IPS are very effective in identifying patterns, they can quickly act
and react on incoming DDoS attacks. This can reduce the DDoS attacks
effectiveness and potentially maintain business continuity for organization.
**4. Physical Security:**
    Security measures implemented on a network will all go to waste if proper physical
    security is not implemented.


```
i. Theft of Equipment: Stealing of equipment belonging to the organization,
ranging from mouse, keyboards, upto laptops, etc.
ii. Tampering with the equipment: If resources such as Access points, routers,
switches are accessible physically some one with knowledge can tamper
with them to gain access to the network.
iii. Unauthorized access: In the given scenario there is no mention of any
physical security measures, if a attacker is able to gain access to all the
resources physically they can easily find a persistence in the network
installing remote backdoor that can exfiltrate sensitive information.
```
## 10. Security Solutions/Recommendations

Following are the security measures to be implemented urgently. We as a consultancy, will provide
some prevention steps so that such types of attacks can be prevented.

Based on our analysis we believe that we need to secure the network of organization. As of
currently implmeneted security measures there are central points of failure like a single firewall to
handle all the incoming and outgoing traffic from the network, there is just one IDS and IPS between
the public and private network although they are efficient but looking at the magnitude of the
network just one is not enough.

Following measures should be implemented as of now:

**1. Palo Alto/ FORTINET NGFW. (auditing and monitoring)
2. SolarWinds SEM. (auditing and monitoring)
3. SentinelOne active EDR and Antivirus. (auditing and monitoring)
4. Acronis DLP. (Access controls and data loss protection)
5. Properly reconfiguring IAM. (Access control)
6. Implementing Physical security for locally hosted servers. (Access control)
7. Securing locally hosted web server. (data encryption and access control)
8. Teaching security practices to the employees. (Training employees)
9. Disaster Management and Recovery plans. (Handling disaster and recovery plans)**


## 11. Products and Features

**1. Palo Alto Networks PA-5400 Series of next-generation firewalls:**
    i. The Palo Alto Networks PA-5400 Series are high-end, enterprise-grade next-
       generation firewalls designed for high-speed data center, internet gateway,
       and service provider deployments. Here are the key highlights of this series:
ii. ML-Powered Next-Generation Firewall: It is marketed as the world's first
machine learning (ML) powered NGFW. It embeds ML capabilities in the core
firewall to provide inline signatureless attack prevention for file-based
threats and zero-day phishing attempts. It also uses ML for automated
policy recommendations.
iii. High Performance: The series offers very high throughput performance, with
the top PA-5445 model providing 90 Gbps firewall throughput, 76 Gbps
threat prevention throughput, and 64 Gbps IPsec VPN throughput. It can
handle up to 48 million concurrent sessions and 449,000 new sessions per
second.
iv. Comprehensive Security: It provides full-stack security with application
visibility/control, user-based policies, SSL/TLS inspection, cloud-delivered
security services (Threat Prevention, WildFire, URL Filtering, DNS Security,
etc.), and single-pass architecture.
v. Visibility for IoT/Unmanaged Devices: Extends visibility and security to all
devices, including unmanaged IoT devices, without needing additional
sensor deployments.
vi. High Availability: Supports active/active and active/passive modes for high
availability deployments.
vii. Centralized Management: Enables centralized administration via the
Panorama network security management platform or Strata Cloud Manager.
viii. VPN support: The PA-5400 series fully supports both IPsec and SSL VPN
capabilities, including the company's own GlobalProtect large scale SSL
VPN solution. Robust encryption, authentication, and key exchange support
is provided for site-to-site and remote user VPN access.
In summary, the PA-5400 series provides machine learning powered inline threat
prevention, high performance and capacity, comprehensive network security


```
functionality, 5G/IoT visibility, high availability, and centralized management -
tailored for large enterprises, data centers and service providers.
```
**2. SolarWinds Security Event Manager (SEM):**
    i. It integrates both the functions of IDS and IPS in Security Event Manager
       (SEM), will be another pair of eyes watching 24/7 for suspicious activity and
       responding in real time to reduce its impact. Minimize the time it takes to
       prepare and demonstrate compliance with audit proven reports and tools
       for HIPAA, PCI DSS, SOX, and more. Virtual appliance deployment, intuitive
       UI, and out-of-the-box content means you can start getting valuable data
       from your logs with minimal expertise and time.
ii. Incidence Response: Quick to analyze data logs and find patterns between
them, well defined data flow. Increases response capabilities, responds to
threat as soon as alarm is triggerd work, Easily configure incident responses
to complex threats.
iii. Automated SIEM monitoring: Improve SIEM monitoring by aggregating logs in
a single location, detect security risks with real-time analysis, monitor
proactively and automate remediation.
iv. File Integrity Monitoring Software: Track file and directory access,
movement, and shares, use a file integrity checker to detect malware
threats, demonstrate FIM security compliance requirements, easily perform
Windows file integrity monitoring.
v. Compliance Reporting Software for IT: Collect and correlate log data to help
satisfy various compliance requirements, generate internal and external
regulatory compliance reports, schedule reports to run automatically or run
as needed.
**3. SentinelOne Active EDR and Antivirus:**
    i. Anti Virus, EPP and EDR do not solve the cybersecurity problem for the
       enterprise. To compensate, some rely on additional services to close the
       gap. But relying on the cloud increases dwell time. Depending on
       connectivity is too late in the game, as it takes only seconds for malicious
       activity to infect an endpoint, do harm, and remove traces of itself. This


```
dependency is what makes the EDR tools of today passive as they rely on
operators and services to respond after it’s already too late. The technology
of TrueContext transforms the EDR to be Active, as it responds in real time,
turning dwell time into no time.
ii. ActiveEDR empowers security teams and IT admins to focus on the alerts
that matter, reducing the time and cost of bringing context to the
complicated and overwhelming amount of data needed with other, passive
EDR solutions.
iii. The introduction of ActiveEDR is similar to other technologies that helped
humans to be more efficient and save time and money. Like the car
replaced the horse and the autonomous vehicle will replace vehicles as we
know them today, ActiveEDR is transforming the way enterprises understand
endpoint security.
iv. Features:
```
1. Combine static and behavioral detections to neutralize known and
    unknown threats.
2. Eliminate analyst fatigue with automated responses to suspicious
    behavior.
3. Proactively prevent threats by extending your endpoint visibility.
4. Build further, customized automations with one API with 350+
    functions.
**4. Acronis Device Lock DLP:**
i. A data loss prevention service offered by Acronis, a SAAS product designed
to prevent unauthorized access to sensitive data in case of device loss or
theft thus defending against data breaches. Having following features:
ii. Device Control and Data Encryption: Encrypt data on both removable and
fixed drives to ensure the safety of sensitive information.
iii. Centralized management and audit reporting: We can control security
policies for many devices and mobile devices centrally.
iv. Endpoint protection integration: Easy to integrate in SIEM.


5. **Properly Reconfiguring IAM:**
    i. Granting least privileges – this means giving minimum permissions for each
       entity and then gradually increasing their privileges according to the need.
ii. MFA – Implmeneting multifactor authentication on places it is required,
although this may slow down some processes but it will make it more
secure.
iii. Rotating credentials – credentials should be rotated periodically as any
credential active for too long increases the risk of compromise.
**6. Physical security measures:**
    i. Using access cards for authorized personnels, limiting access to important
       resources to the assigned individuals. Implementing biometric
       authentication and authorization with MFA. Setting up surveillance for the
       resource rooms that are monitored 24/7. Maintaining logs of people
       accessing these records.
**7. Securing locally hosted web server:**
    i. The website is the only thing that is accessible outside of the network, we
       need to sanitize and handle all the incoming and outgoing packets properly
       to stop or remove any suspicious activity. Following are some of the
       measures that can be taken to secure the web server:
          1. SSL/TLS encryption: These two protocols provide transparent
             certificates for the client as well as for the server side to maintain the
             integrity of their HTTP transaction. They encrypt the communication,
             and make them unique only the client and server can understand the
             information being shared in the communication medium.
          2. Access Control: Utilizing string passwords, limiting access to the
             server to authorized users, and putting multi-factor authentication
             into place.
          3. Content Security Policy: Developers can put a limits on the content
             being displayed on the page and what parameters the user can
             interact with.


4. Web application Firewall: cloudflare firewall is well documented and
    applied widely and is the most reliable WAF, it maintains logs,
    admins can easily apply ACLs, and is very effective in analyzing and
    alerting about malicious packet behaviour.
**8. Teaching security practices to the employees:**
The weakest link in a security infrastructure is a human, they are the most
susceptible to getting exploited and easily manipulated to do others biding.
Following are some security measures you can implement to educate them on it:
i. Education and testing: Employees should be trained on how to handle
external emails and abnormal emails, what information can be disclosed
and what information should not be disclosed during a conversation with
anyone in organization and outside of organization. After educating them,
they should also perform an assessment on a periodic basis to understand
what more improvements can be done to the training and how the
employees can be stopped from being exploited.
ii. Policies and procedures: It is important to educate the employees on the
companies policies and procedures. This includes reporting incidents to IT
and adhering to the organization’s incident response policies.
**9. Disaster management and Data recovery plans:
i. Data Backup Plan:**
1. Establish procedures for regular and secure backups of PHI and
other critical data, both electronic and paper-based.
2. Implement off-site storage of backup data in a secure location,
preferably at a geographically separate site.
3. Ensure that backup data is encrypted and access is restricted to
authorized personnel.
**ii. Disaster Recovery Plan:**
1. Define roles and responsibilities for disaster response and recovery
teams.
2. Outline procedures for restoring data and systems from backups in
the event of a disaster.


3. Identify alternate sites or locations for operations if the primary site
    is unavailable.
4. Establish procedures for maintaining business continuity and
    minimizing disruptions to critical services.
**iii. Emergency Mode Operation Plan:**
1. Develop procedures for operating in emergency mode if systems or
facilities are compromised.
2. Define methods for maintaining access to PHI and essential
operations during an emergency.
3. Establish protocols for secure communication and coordination
among personnel during an emergency.
**iv. Testing and Maintenance:**
1. Regularly test and update the disaster management and data
recovery plan to ensure its effectiveness and accuracy.
2. Conduct simulations or drills to evaluate the plan and identify areas
for improvement.
3. Maintain up-to-date documentation and training materials for all
relevant personnel.
**v. Contingency Planning:**
1. Identify alternative methods for providing critical services if primary
systems or facilities are unavailable.
2. Establish agreements or contracts with third-party vendors or
service providers for emergency support if needed.
**vi. Incident Response and Reporting:**
1. Develop procedures for detecting, reporting, and responding to
security incidents or data breaches.
2. Outline the process for notifying appropriate authorities, such as the
Department of Health and Human Services (HHS), in the event of a
breach involving PHI.
**vii. Workforce Training:**


1. Provide regular training to all workforce members on the disaster
    management and data recovery plan, their roles and responsibilities,
    and the importance of adhering to HIPAA guidelines.

## 12. Zero Trust Security Model for Healthcare Infrastructure

**1. HIPAA Compliance:**
- Access Control: Zero Trust enforces granular access controls throughout the healthcare
infrastructure, ensuring that only authorized personnel can access sensitive patient data stored in
the Linux network. This includes implementing role-based access control (RBAC) and multifactor
authentication (MFA) mechanisms.
- Encryption: All data, including electronic protected health information (ePHI), is encrypted both
at rest and in transit within the network. This encryption extends to communication channels
between the web server in the DMZ and backend servers to safeguard patient privacy and
confidentiality.
- Continuous Monitoring: The Zero Trust model incorporates real-time monitoring of network
traffic and user activities, enabling the detection of anomalous behavior or potential security
threats. This proactive approach aligns with HIPAA's requirement for continuous security
monitoring and incident response.
**2. GDPR Compliance:**
- Data Protection: Zero Trust employs robust encryption techniques to protect personal data
stored within the healthcare infrastructure, such as patient medical records and research data.
Additionally, access controls are strictly enforced to ensure that only authorized personnel can
access and process personal data.
- Accountability and Governance: Identity and access management (IAM) solutions are
implemented to maintain accountability by tracking user access and activities across the network.
Detailed audit logs provide visibility into data handling practices, supporting compliance with
GDPR's accountability and governance requirements.
- Data Breach Notification: Zero Trust's continuous monitoring capabilities enable rapid detection
and response to data breaches, ensuring compliance with GDPR's data breach notification


obligations. Incident response procedures are in place to promptly investigate and mitigate any
security incidents that may occur.

**3. SOC 2 Compliance:**
- Security and Availability: The Zero Trust model enhances security and availability by
implementing network segmentation to isolate critical systems and protect customer data. This
includes securing the web server in the DMZ and backend servers within the Windows and Linux
networks to prevent unauthorized access.
- Monitoring and Incident Response: Real-time monitoring tools are deployed to monitor network
traffic, detect security incidents, and respond promptly to any threats or vulnerabilities. Incident
response plans are documented and tested regularly to ensure readiness in the event of a security
breach.
- Trust Services Criteria: Zero Trust aligns with SOC 2's Trust Services Criteria by addressing key
principles such as security, availability, processing integrity, confidentiality, and privacy. By
adopting a comprehensive approach to security and compliance, the healthcare infrastructure can
demonstrate adherence to SOC 2 requirements.

In summary, the Zero Trust Security Model provides a robust framework for securing the healthcare
infrastructure described in the scenario while ensuring compliance with HIPAA, GDPR, and SOC 2
regulations. By implementing strict access controls, encryption measures, continuous monitoring,
and incident response capabilities, the organization can protect sensitive patient data, maintain
operational resilience, and mitigate the risk of security breaches.


## 13. High-level architecture diagram after improvement:


## 14. Cost Estimation

**Annual Subscription Costs**

- SentinelOne AV: $3,600
- SentinelOne XDR: $7,200
- SolarWinds SEM: $3,510
- Acronis Device Lock DLP: $3,510
- Web Application Firewall (WAF): $3,000
- IAM implementation: $18,000
- Security Engineer consultation: $100,000
- Training and Awareness: $50,000
- Compliance risk assessment: $37,000
- Email Security Subscription: $15,000

**One-time Purchase Costs:**

- Palo Alto Networks PA-5400 Series NGFWs: $70,000
- Physical Security: $30,000
- Overall Risk Assessment: $20,000
- Disaster Recovery Assessment: $20,000
- VAPT: $38,000
**Total Cost**
- Total Annual Subscriptions Cost: $240,320
- Total One-time Cost: $178,000
- Total Cost (Annual + One-time): $418,320
- Budget Left = $81,680


The residual budget presents an opportunity to augment our security infrastructure by enlisting the
expertise of a junior security analyst. This addition would fortify our defense strategy by enhancing
our capacity for threat detection, incident response, and security operations. Leveraging this
allocation, we can bolster our team's capabilities in proactively identifying and mitigating potential
vulnerabilities, conducting comprehensive security assessments, and reinforcing our adherence to
regulatory compliance standards. The inclusion of a junior security analyst underscores our
commitment to maintaining a robust security posture and fortifying our organizational resilience
against evolving cyber threats.

```
240,320
```
```
178,000
```
```
81,680
```
## Total Cost = 500,000

```
Total Annual Subscriptions Cost Total One-time Cost Budget Left
```

## 15. References

1. https://www.logicworks.com/blog/2015/05/aws-iam-security-cloud-hipaa-compliance/
2. https://public3.pagefreezer.com/browse/HHS.gov/20- 06 -
    2023T05:11/https://www.hhs.gov/sites/default/files/nist-csf-to-hipaa-security-rule-
    crosswalk- 02 - 22 - 2016 - final.pdf
3. https://www.solarwinds.com/kiwi-syslog-server/integrations/security-event-
    manager?CMP=KNC-TAD-GGL-SW_NA_X_PP_CPC_LD_EN_PBOS_X-
    SS&gad_source=1&gclid=CjwKCAjwl4yyBhAgEiwADSEjeGQRbpKTdoowXey2F22tL_vWx7pD
    ZigtLJ4SB1pizkCn252rMCF3FRoCMYoQAvD_BwE&gclsrc=aw.ds
4. https://www.acronis.com/en-us/products/cloud/cyber-protect/data-loss-prevention/
5. https://www.sentinelone.com/platform/?utm_source=google-paid&utm_medium=paid-
    search&utm_campaign=nam-brand-brd-
    ppc&utm_term=sentinelone%20edr&campaign_id=11854731743&ad_id=674099731635&g
    ad_source=1&gclid=CjwKCAjwl4yyBhAgEiwADSEjeMdsQYQUTT5X3hEEoOROGC_vCixOrpn
    dGcEzbqVR7qrJ8RejOULHNBoCc6QQAvD_BwE
6. https://www.paloaltonetworks.com/resources/datasheets/pa- 5400 - series
7. https://www.cloudflare.com/learning/security/glossary/what-is-zero-
    trust/#:~:text=Zero%20Trust%20security%20means%20that,shown%20to%20prevent%20
    data%20breaches.
8. https://www.checkpoint.com/cyber-hub/cyber-security/what-is-soc- 2 -
    compliance/#:~:text=SOC%202%20is%20a%20voluntary,processing%20integrity%2C%20
    confidentiality%2C%20privacy.
9. https://gdpr-info.eu/
10. https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
11. https://aws.amazon.com/iam/


****Security Solution for Healthcare Infrastructure**

### Team Members:
- Arbaaz Jamadar
- Srinivasan Anandan
- Mitraj Parmar

---

## Table of Contents

1. [Overview](#1-overview)
2. [Objective](#2-objective)
3. [Cybersecurity Incident Analysis](#3-cybersecurity-incident-analysis)
4. [Security Improvement Plan Methodology](#4-security-improvement-plan-methodology)
5. [Potential Threats and Their Implications](#5-potential-threats-and-their-implications)
6. [Current Network Architecture](#6-current-network-architecture)
7. [STRIDE Model](#7-stride-model)
8. [DREAD Model](#8-dread-model)
9. [Prioritizing the Risks](#9-prioritizing-the-risks)
10. [Security Solutions/Recommendations](#10-security-solutionsrecommendations)
11. [Products and Features](#11-products-and-features)
12. [Security Model](#12-zero-trust-security-model-for-healthcare-infrastructure)
13. [Improved Infrastructure](#13-improved-infrastructure)
14. [Cost Estimation](#14-cost-estimation)
15. [References](#15-references)

---

## 1. Overview

Our healthcare system's IT infrastructure recently experienced a severe breach, resulting in the compromise of several computers within our network. This breach has inflicted significant damage, particularly within our Linux network environment, which houses critical research data vital to our organization, as well as sensitive information such as patients' PII and health-related data. 

Initial access was achieved by exploiting a command injection vulnerability in our web server which hosts our website, that is utilized by patients, doctors, and customer support to interact with the healthcare system digitally. Leveraging this foothold, the attacker detected a private Windows network connected to the DMZ and successfully pivoted into the Windows environment. Exploiting misconfigured network devices, such as insecure firewall rules or improperly configured VPN gateways, unauthorized access was gained to multiple systems within the network. 

Upon infiltrating the Windows network, thorough reconnaissance revealed the presence of Samba services on a domain controller, hinting at a separate Linux network. Subsequent investigation unveiled communication between the Windows domain controller's Samba service and IP addresses outside the local subnet, indicating the existence of the Linux network. Capitalizing on this revelation, the attacker exploited a host-based vulnerability on a Windows server to elevate privileges and breach the Linux network. Once inside, further exploitation of vulnerabilities ensued, resulting in escalated privileges and persistent access, facilitating data exfiltration and malicious activity within the Linux environment.

This breach not only inflicted significant financial losses but also tarnished our organization's reputation due to the prolonged undetected presence of the attackers within our network for over two months. As a result, our company's leadership has prioritized the enhancement of our IT security posture, necessitating urgent action while mindful of budgetary constraints. The primary objective is to preemptively detect and mitigate security threats before they penetrate our network, thereby averting substantial losses. Furthermore, addressing potential data leakage vulnerabilities is imperative to fortify our defensive security posture. 

As consultants tasked with evaluating and proposing a solution, our aim is to bolster the organization's security defenses, prevent future cyber attacks, and expedite detection in the event of a successful breach.

To accomplish this goal, we are entrusted with implementing defensive strategies to combat security threats. The allocated budget of **$500,000** will cover the acquisition of necessary hardware and software, along with the recruitment of two full-time security administrators for the initial year. Our proposed solution will encompass a comprehensive array of security measures tailored to mitigate vulnerabilities and enhance threat detection capabilities across both our Linux and Windows networks. Through meticulous planning and strategic deployment of resources, we aim to fortify our organization's security posture, safeguard critical data assets, and safeguard against future cyber threats.

---

## 2. Objective

Our healthcare system's security objectives are paramount in safeguarding our assets and ensuring operational continuity. Prioritizing these objectives aligns with our core business operations and enables the effective allocation of resources to address critical security concerns.

### 1. Protecting Intellectual Property and Research Data
Safeguarding the integrity and confidentiality of research data, patients' health-related data, personally identifiable information (PII), and intellectual property stored within the Linux network.

**Prioritization:** Given that our organization relies heavily on research data for scientific advancements and medical development, as well as patient data, protecting intellectual property should be a top priority. This is particularly crucial in the context of a research-focused company where proprietary information is a key asset.

### 2. Maintaining Operational Continuity
Ensuring uninterrupted business operations and availability of critical systems and services, including the web server used for seamless interaction between patient, doctors and customer support.

**Prioritization:** Operational continuity is vital for sustaining revenue streams and customer satisfaction, making it a high-priority objective.

### 3. Protecting Customer Data and Trust
Safeguarding patients' data stored on the web server and database server, as well as ensuring compliance with privacy regulations, are essential for maintaining customer trust.

**Prioritization:** In the healthcare sector, adherence to the Health Insurance Portability and Accountability Act (HIPAA) is crucial. HIPAA sets strict standards for the protection of patients' sensitive health information, mandating measures such as encryption, access controls, and regular audits to ensure data security. Compliance with HIPAA not only safeguards patients' privacy but also fosters trust between healthcare providers and their clientele.

### 4. Enabling Secure Remote Work
**Objective:** Ensuring the security of remote work environments, including laptops issued to employees, to facilitate increased work-from-home capabilities.

**Prioritization:** With a significant portion of personnel working remotely, securing remote access and endpoints becomes critical to prevent unauthorized access and data breaches.

By aligning the proposed security objectives with the company's core business operations and priorities, we can develop a comprehensive security solution that effectively mitigates risks and protects critical assets while supporting the organization's strategic goals.

---

## 3. Cybersecurity Incident Analysis

Our healthcare organization recently experienced attacks that can be primarily classified into two types: ransomware attacks, which are among the most common threats to healthcare systems, and data breaches. At the time of these attacks, the following measures were implemented to prevent such incidents:

### Existing Security Measures

1. **Firewalls and Intrusion Detection/Prevention Systems (IDS/IPS):** A single set of firewall and IDS/IPS system is implemented at network boundaries between the DMZ, internet, and private networks to monitor and filter incoming and outgoing traffic, thereby preventing unauthorized access and detecting suspicious activity effectively.

2. **Antivirus and Antimalware Software:** Endpoint protection software, such as antivirus and antimalware tools, has been installed on every device within the healthcare system. This software is instrumental in detecting and removing malicious software, including ransomware, from individual devices such as desktops and servers.

3. **Data Encryption:** Given the sensitive nature of the data within our healthcare system, including Personally Identifiable Information (PII) of patients, robust encryption measures have been employed. Data is encrypted both in transit and at rest to safeguard it from unauthorized access in the event of a breach. Transport Layer Security (TLS/SSL) protocols are utilized for protecting data in transit, while Data Encryption Standard (DES) is implemented to encrypt data at rest.

4. **Employee Training and Awareness:** A comprehensive security awareness training program has been implemented to educate all personnel about cybersecurity best practices. This initiative equips employees with the knowledge to recognize phishing attempts and other social engineering tactics commonly used in ransomware attacks, thereby bolstering the organization's overall security posture.

5. **Access Control and Least Privilege Principle:** Adhering to the principle of least privilege, access to sensitive systems and data is strictly controlled within our organization. Access privileges are granted only to authorized personnel on a need-to-know basis, effectively reducing the risk of unauthorized access and potential data breaches.

### Identified Gaps

Despite having implemented all the measures aimed at preventing ransomware attacks and data breaches within our healthcare infrastructure, a significant security incident occurred. Upon conducting a thorough investigation post-attack, it became evident that several gaps existed due to lax enforcement of policies and inadequate monitoring. These gaps are outlined as follows:

1. **Insufficient User Training:** Although cybersecurity training programs were available, not all employees took them seriously or received adequate training. Consequently, an employee fell victim to a phishing email containing ransomware, which managed to bypass the antivirus software.

2. **Insufficient Monitoring and Detection:** One significant gap in the healthcare infrastructure lies in its reliance on a single set of firewall and IDS/IPS systems. This configuration creates a bottleneck in traffic inspection and reduces monitoring effectiveness, thereby increasing the risk of attackers evading detection and exploiting vulnerabilities. To address this issue, implementing a defense-in-depth approach with segmented networks and multiple security layers can enhance monitoring and detection capabilities, ultimately reducing the likelihood of successful ransomware attacks and data breaches.

3. **Inadequate Endpoint Security:** Inadequate patch management allowed vulnerabilities within the system to remain unaddressed, providing attackers with entry points into the infrastructure. This failure stemmed from gaps in the patch management process, including delays in applying critical security patches and ineffective prioritization of patching efforts.

4. **Weak Access Controls and Data Encryption:** Weak access controls and data encryption were significant vulnerabilities in the healthcare infrastructure. Access controls were lax, allowing the ransomware to laterally traverse the network, compromising sensitive data on both Windows administration and Linux research machines. Moreover, data confidentiality and integrity during transit relied solely on SSL/TLS version 1.1, which is plagued with vulnerabilities. To safeguard data at rest, the infrastructure employed the DES algorithm, which is considered insufficiently robust. As a result, compliance with HIPAA regulations was compromised, leading to potential legal consequences.

5. **Inadequate Incident Response Planning:** The organization lacked a robust incident response plan for promptly detecting, containing, and mitigating security incidents. Additionally, there were gaps in communication and coordination among stakeholders during incident response efforts, resulting in delays in identifying and responding to the breach.

6. **Lack of Backup Strategy:** Despite regular backups, their storage lacked offsite security (employing DES encryption for data at rest) and reliability testing. Consequently, the restoration process became protracted and uncertain, exacerbating the ransomware attack's impact.

While the healthcare infrastructure has implemented basic measures to prevent ransomware attacks and data breaches, several gaps and failures contributed to the successful breach. Addressing these issues necessitates a comprehensive approach, encompassing the enhancement of monitoring and detection capabilities, improvement of endpoint security, prioritization of patch management, reinforcement of user awareness training, and development of a robust incident response plan.

---

## 4. Security Improvement Plan Methodology

1. **Gap Analysis and Prioritization:** Conduct a comprehensive gap analysis to identify all vulnerabilities and weaknesses in the current security posture. Prioritize these gaps based on their severity and potential impact on the organization's operations and data security.

2. **Enhanced User Training and Awareness:** Develop and implement an enhanced cybersecurity training program for all employees, emphasizing the importance of vigilance against phishing attempts and other social engineering tactics. Regular phishing simulations should be conducted to test and reinforce employees' awareness and response to potential threats.

3. **Segmented Network Architecture:** Implement a segmented network architecture with separate zones for the DMZ, Windows administration network, Linux research network, and VPN-connected remote users. Deploy dedicated firewalls and intrusion detection/prevention systems for each zone to enhance monitoring and detection capabilities and minimize the risk of lateral movement by attackers.

4. **Endpoint Security Enhancement:** Strengthen endpoint security by improving patch management processes to ensure timely application of security patches and updates. Deploy advanced endpoint protection solutions capable of detecting and blocking sophisticated malware, including ransomware. Implement endpoint detection and response (EDR) solutions to proactively detect and respond to suspicious activity on endpoints.

5. **Access Control and Data Encryption:** Enforce strict access controls based on the principle of least privilege to limit users' access to sensitive systems and data. Implement robust data encryption protocols, such as Advanced Encryption Standard (AES), for data at rest and in transit to ensure confidentiality and integrity.

6. **Incident Response Plan Development:** Develop and implement a comprehensive incident response plan outlining procedures for detecting, containing, and mitigating security incidents. Define roles and responsibilities for incident response team members and establish communication channels for timely coordination and decision-making during security incidents.

7. **Backup and Recovery Strategy:** Enhance the backup and recovery strategy by implementing offsite storage solutions with robust encryption to safeguard backups from ransomware attacks. Regularly test backup integrity and reliability to ensure prompt and successful recovery in the event of a security incident.

8. **Continuous Monitoring and Improvement:** Implement continuous monitoring mechanisms to detect and respond to security threats in real-time. Conduct regular security audits and assessments to evaluate the effectiveness of security controls and identify areas for further improvement.

9. **Employee Engagement and Accountability:** Foster a culture of cybersecurity awareness and accountability among employees by promoting active participation in security initiatives and encouraging reporting of suspicious activities. Recognize and reward employees for their contributions to maintaining a secure environment.

10. **Regular Training and Review:** Conduct regular training sessions and security awareness programs to keep employees updated on emerging threats and best practices. Review and update security policies, procedures, and controls periodically to adapt to the evolving cybersecurity landscape and regulatory requirements.

By implementing this methodology, the healthcare organization can address and improve its security posture, mitigating the risk of future cybersecurity incidents and ensuring the confidentiality, integrity, and availability of sensitive data and critical systems.

---

## 5. Potential Threats and Their Implications

1. **Ransomware Attacks:** Ransomware poses a significant threat to healthcare organizations, encrypting critical data and systems and demanding ransom payments for decryption keys. Such attacks can disrupt healthcare services, compromise patient care, and result in financial losses and reputational damage.

2. **Data Breaches:** Data breaches can occur due to various factors, including unauthorized access to sensitive patient information, inadequate security controls, and insider threats. Breached patient data can be exploited for identity theft, financial fraud, or other malicious purposes, leading to legal liabilities, regulatory penalties, and damage to the organization's reputation.

3. **Phishing and Social Engineering:** Phishing emails and social engineering tactics are commonly used by attackers to trick employees into disclosing sensitive information or downloading malware onto their devices. Successful phishing attacks can compromise user credentials, facilitate unauthorized access to network resources, and serve as entry points for ransomware and other malware.

4. **Insider Threats:** Insiders, including employees, contractors, or partners with access to sensitive data and systems, can pose a significant threat to healthcare organizations. Insider threats may involve malicious actions, such as unauthorized data access or exfiltration, or inadvertent behaviors, such as negligence or unintentional data disclosure, resulting in data breaches and operational disruptions.

5. **Exploitation of Vulnerabilities:** Exploiting vulnerabilities in software, applications, or network infrastructure is a common tactic used by cybercriminals to gain unauthorized access to healthcare systems. Failure to promptly patch known vulnerabilities can leave systems and devices susceptible to exploitation, leading to data breaches, system compromise, and potential disruption of healthcare services.

6. **Denial of Service (DoS) Attacks:** DoS attacks aim to disrupt the availability of healthcare services by flooding network resources, servers, or applications with excessive traffic, rendering them inaccessible to legitimate users. Such attacks can result in downtime, service interruptions, and loss of patient trust and confidence in the organization's ability to deliver timely care.

7. **Malware Infections:** Malware infections, including viruses, Trojans, and spyware, can compromise the integrity and confidentiality of healthcare data, disrupt critical systems and operations, and facilitate unauthorized access by attackers. Malware may be distributed through malicious websites, email attachments, or removable storage devices, posing a constant threat to healthcare organizations' IT infrastructure.

8. **Unauthorized Access and Privilege Escalation:** Unauthorized access to sensitive systems and data, coupled with privilege escalation, can enable attackers to gain extensive control over healthcare networks and resources. Attackers may exploit weak access controls, stolen credentials, or misconfigured permissions to escalate privileges and move laterally within the network, increasing the risk of data breaches and system compromise.

---

## 6. Current Network Architecture

### Network Components

1. **DMZ (Demilitarized Zone):**
   - Contains the web server hosting the web portal accessible to patients, doctors, and customer support.
   - Provides a buffer between the internal network and external internet traffic.

2. **Windows Network:**
   - Manages the entire IT infrastructure of the healthcare system.
   - Responsible for access control and authentication for patients and customers.
   - Connected to both the Linux network and DMZ to manage and update both networks.

3. **Linux Network:**
   - Stores crucial data related to patients and research work.
   - Most doctors operate through this network.
   - Acts as the data server of the IT infrastructure.

4. **VPN Connection:**
   - Facilitates secure connections for employees working remotely.
   - Provides a secure tunnel for remote access to the internal network resources.
   - Ensures confidentiality and integrity of data transmitted over the internet.

5. **Web Application Firewall (WAF):**
   - Implements a layer of defense against web-based attacks.
   - Filters and monitors HTTP traffic to and from the web server.
   - Detects and blocks malicious activity, such as SQL injection and cross-site scripting (XSS) attacks.

6. **Network Segmentation:**
   - Divides the network into smaller segments or zones.
   - Isolates critical systems and sensitive data from the rest of the network.
   - Limits the scope of a breach and prevents lateral movement by attackers.

7. **Access Controls and Authentication Mechanisms:**
   - Enforces strict access controls to ensure that only authorized users can access sensitive resources.
   - Implements robust authentication mechanisms, such as multi-factor authentication (MFA) or biometric authentication.
   - Validates user identities and authorizes access based on predefined permissions and roles.

8. **Encryption of Sensitive Data:**
   - Protects confidential information by encrypting it at rest and in transit.
   - Secures data stored on servers or databases by encrypting it using cryptographic algorithms.
   - Safeguards data transmitted over the network by encrypting communication channels with protocols like SSL/TLS.

### HIPAA Compliance

HIPAA (Health Insurance Portability and Accountability Act) is a federal law that sets standards for protecting the privacy and security of individuals' protected health information (PHI). HIPAA cybersecurity compliance is essential for any organization that deals with PHI, such as healthcare providers, health plans, and healthcare clearinghouses.

#### Key Aspects of HIPAA Cybersecurity Compliance:

1. **Risk Analysis and Risk Management:** Organizations must conduct a thorough risk analysis to identify potential threats and vulnerabilities to the confidentiality, integrity, and availability of protected health information (PHI). Based on the risk analysis, they must implement appropriate risk management measures to mitigate identified risks.

2. **Access Controls:** HIPAA requires implementing technical and physical safeguards to limit access to PHI to only authorized individuals and processes. This includes measures such as unique user identification, emergency access procedures, and automatic logoff mechanisms.

3. **Audit Controls:** Organizations must implement hardware, software, and/or procedural mechanisms to record and examine activity in information systems that contain or use PHI.

4. **Integrity Controls:** These controls are designed to protect PHI from improper alteration or destruction. They include measures such as electronic mechanisms to corroborate data integrity and procedures to verify that PHI has not been altered or destroyed in an unauthorized manner.

5. **Transmission Security:** HIPAA requires implementing technical security measures to guard against unauthorized access to PHI transmitted over electronic communications networks.

6. **Contingency Planning:** Organizations must establish policies and procedures for responding to emergencies or other occurrences that could damage systems containing PHI. This includes data backup plans, disaster recovery plans, and emergency mode operation plans.

7. **Workforce Training and Management:** HIPAA requires providing appropriate training to workforce members on policies and procedures related to PHI security, as well as applying appropriate sanctions against workforce members who violate these policies and procedures.

8. **Regular Security Evaluations:** Organizations must periodically evaluate their security measures to ensure they continue to provide adequate protection.

#### HIPAA Compliance Gaps

To achieve HIPAA compliance, the organization needs to address these identified gaps and implement the necessary technical, administrative, and physical safeguards required by the HIPAA Security Rule and Privacy Rule.

1. **Inadequate Access Controls and Data Encryption:**
   - Weak access controls and data encryption were significant vulnerabilities in the healthcare infrastructure. Specifically:
     - Access controls were lax, allowing the ransomware to laterally move across the network and compromise sensitive data on both Windows administration and Linux research machines.
     - Data in transit relied solely on the outdated and insecure SSL/TLS 1.1 protocol for encryption.
     - Data at rest was encrypted using the DES algorithm, which is considered insufficiently robust and no longer meets HIPAA standards.

2. **Lack of Comprehensive Risk Assessments and Risk Management:**
   - There is no mention of regular risk assessments or risk management plans being conducted to identify and mitigate potential vulnerabilities related to the storage, transmission, and handling of protected health information (PHI). Failure to assess and address risks can lead to HIPAA compliance gaps.

3. **Insufficient Auditing and Monitoring:**
   - The organization relied on a single set of firewall and IDS/IPS systems, which created a bottleneck in traffic inspection and reduced monitoring effectiveness. Inadequate monitoring and auditing of access to PHI can lead to HIPAA violations going undetected.

4. **Gaps in Employee Training and Awareness:**
   - While the organization had a security awareness training program, not all employees took it seriously or received adequate training. Lack of proper employee training best practices for handling PHI can lead to compliance violations.

5. **Inadequate Incident Response and Disaster Recovery Planning:**
   - The organization lacked a robust incident response plan for promptly detecting, containing, and mitigating security incidents. Additionally, there were gaps in communication and coordination during incident response efforts. Failure to have proper incident response and disaster recovery plans in place can lead to HIPAA violations in the event of a data breach or system failure.

As per the gaps found and categorized we have prioritized risks and developed a plan to address implement proper security procedures and measures.

---

## 7. STRIDE Model

| Threat | Property Violated | Threat Definition |
|--------|-------------------|-------------------|
| **Spoofing** | Authentication | 1. Attackers could spoof identities to gain unauthorized access to systems and data (e.g., spoofing doctor or patient identities)<br>2. Spoofing of IP addresses to bypass access controls<br>3. Spoofing of HTTPS certificates for man-in-the-middle attacks |
| **Tampering** | Integrity | 1. Tampering with data in transit (e.g., modifying patient records, prescriptions)<br>2. Tampering with configuration files or system logs<br>3. Tampering with software updates or security patches |
| **Repudiation** | Non-repudiation | 1. Users denying their actions or activities on the systems<br>2. Lack of auditing or insufficient audit logs<br>3. Inability to prove data integrity or origin |
| **Information Disclosure** | Confidentiality | 1. Disclosure of sensitive patient data (PHI) due to data breaches<br>2. Disclosure of intellectual property or research data<br>3. Inadvertent disclosure by insiders (e.g., misconfigured permissions)<br>4. Insider threats (e.g., disgruntled employees, contractor misconduct) |
| **Denial of Service** | Availability | 1. DoS attacks on web servers or network infrastructure<br>2. Distributed DoS (DDoS) attacks on critical systems<br>3. Malware infections (e.g., ransomware, trojans)<br>4. Physical security threats (e.g., theft, unauthorized access to facilities) |
| **Elevation of Privilege** | Authorization | 1. Exploiting software vulnerabilities for privilege escalation<br>2. Insecure configurations leading to unauthorized elevated access<br>3. Unauthorized lateral movement within the network |

---

## 8. DREAD Model

The measuring scale will be 1 (low), 2 (intermediate), 3 (High).

| Threat | D | R | E | A | D | Total |
|--------|---|---|---|---|---|-------|
| Data Breaches | 3 | 2 | 2 | 3 | 1 | 11 |
| Malware Infections | 3 | 3 | 2 | 3 | 1 | 13 |
| Exploiting Code Flaw | 3 | 2 | 2 | 3 | 2 | 12 |
| Database vulnerabilities | 3 | 1 | 1 | 3 | 1 | 9 |
| Phishing/Social Engineering | 3 | 3 | 3 | 3 | 3 | 15 |
| Software Vulnerabilities | 1 | 1 | 1 | 1 | 1 | 5 |
| Denial of Service | 1 | 3 | 2 | 3 | 1 | 10 |
| Weak Credentials | 2 | 1 | 1 | 1 | 1 | 6 |
| Physical Access | 3 | 1 | 1 | 3 | 1 | 9 |
| Malicious Insider | 2 | 2 | 1 | 3 | 1 | 9 |

---

## 9. Prioritizing the Risks

As per the observations we have created a list of risks and their priorities, the priority list is as follows:

### 1. Securing Webservers
These servers hold sensitive information like usernames and passwords that can help an attacker gain access to:

- **Command injection:** The attacker was able to gain access to network by exploiting the command injection vulnerability on the website. They used this vulnerability to create a payload which created a reverse shell on the server that hosted the website and then used other TTPs to find persistence on the machine.

- **Information Disclosure:** Absence of Web application firewall (WAF) can cause information disclosure. This vulnerability allows attackers to obtain sensitive information like usernames and passwords.

- **SQL injection:** The website trusts user input, the website queries the database to retrieve product details and user details. If the user input is trusted and no sanitization measures are applied to it. It is possible to obtain a motherload of information from SQL injection attacks.

### 2. Firewall

- The implemented firewalls function solely as packet filtering mechanisms, characterized by their static evaluation of inbound packets against predefined criteria, including permitted IP addresses, packet attributes such as type and port number, and other elements of the packet protocol headers. This method entails the omission of packet routing functionality; instead, packets are scrutinized individually, and those failing to meet the established criteria are summarily discarded, thereby terminating their transmission without further processing. It filters traffic based on MAC addresses and has no visibility of higher-level protocols, it is easy to bypass these kind of firewall by using high-level protocols. It can also be bypassed by MAC spoofing. These firewalls are widely implemented because of low computation and extremely fast and efficient for scanning traffic.

- **Inefficient Scalability:**
  - The management of a sophisticated network, characterized by a diverse array of high-level and low-level protocols facilitating numerous requests and packet transmissions, poses significant challenges for a layer 2 firewall. Moreover, the dynamic nature of network traffic necessitates real-time rule implementation, a task hindered by the inherent limitations of firewalls. To effectively mitigate online threats, a holistic approach is imperative, wherein layer 2 firewalls are supplemented with complementary security measures to provide comprehensive protection.

### 3. Proper Implementation of IDS and IPS

A network that lacks proper implementation of an intrusion detection system (IDS) and intrusion prevention system (IPS) is susceptible to several cyber dangers, such as:

- **Unauthorized access:** IDS can detect and alert about unauthorized access, but intrusion prevention detects and tries to prevent unauthorized access. IDS can be integrated easily while IPS needs some time to install and need to be maintained periodically.

- **Malware and Ransomware:** An IDS and IPS that works on a network layer can analyze packets and identify patterns in networking that may be suspicious and may in case of IDS alert and in case of IPS alert and prevent any malicious activity. Ransomware and malware usually communicate with C2 servers, and for one time deployment of malwares and ransomwares a Host based IDS and Host based IPS can be more effective.

- **Insider Threat:** as IDS and IPS analyze logs and user behavior patterns, they can establish patterns between unauthorized access request or access requests to resources they don't have access to this can help delve deeper into whether the accounts were compromised or whether there was a insider who was trying to gain access to restricted resources.

- **DDoS:** as IDS and IPS are very effective in identifying patterns, they can quickly act and react on incoming DDoS attacks. This can reduce the DDoS attacks effectiveness and potentially maintain business continuity for organization.

### 4. Physical Security

Security measures implemented on a network will all go to waste if proper physical security is not implemented.

- **Theft of Equipment:** Stealing of equipment belonging to the organization, ranging from mouse, keyboards, up to laptops, etc.

- **Tampering with the equipment:** If resources such as Access points, routers, switches are accessible physically some one with knowledge can tamper with them to gain access to the network.

- **Unauthorized access:** In the given scenario there is no mention of any physical security measures, if a attacker is able to gain access to all the resources physically they can easily find a persistence in the network installing remote backdoor that can exfiltrate sensitive information.

---

## 10. Security Solutions/Recommendations

Following are the security measures to be implemented urgently. We as a consultancy, will provide some prevention steps so that such types of attacks can be prevented.

Based on our analysis we believe that we need to secure the network of organization. As of currently implemented security measures there are central points of failure like a single firewall to handle all the incoming and outgoing traffic from the network, there is just one IDS and IPS between the public and private network although they are efficient but looking at the magnitude of the network just one is not enough.

### Following measures should be implemented as of now:

1. Palo Alto/ FORTINET NGFW (auditing and monitoring)
2. SolarWinds SEM (auditing and monitoring)
3. SentinelOne active EDR and Antivirus (auditing and monitoring)
4. Acronis DLP (Access controls and data loss protection)
5. Properly reconfiguring IAM (Access control)
6. Implementing Physical security for locally hosted servers (Access control)
7. Securing locally hosted web server (data encryption and access control)
8. Teaching security practices to the employees (Training employees)
9. Disaster Management and Recovery plans (Handling disaster and recovery plans)

---

## 11. Products and Features

### 1. Palo Alto Networks PA-5400 Series of Next-Generation Firewalls

The Palo Alto Networks PA-5400 Series are high-end, enterprise-grade next-generation firewalls designed for high-speed data center, internet gateway, and service provider deployments. Here are the key highlights of this series:

- **ML-Powered Next-Generation Firewall:** It is marketed as the world's first machine learning (ML) powered NGFW. It embeds ML capabilities in the core firewall to provide inline signatureless attack prevention for file-based threats and zero-day phishing attempts. It also uses ML for automated policy recommendations.

- **High Performance:** The series offers very high throughput performance, with the top PA-5445 model providing 90 Gbps firewall throughput, 76 Gbps threat prevention throughput, and 64 Gbps IPsec VPN throughput. It can handle up to 48 million concurrent sessions and 449,000 new sessions per second.

- **Comprehensive Security:** It provides full-stack security with application visibility/control, user-based policies, SSL/TLS inspection, cloud-delivered security services (Threat Prevention, WildFire, URL Filtering, DNS Security, etc.), and single-pass architecture.

- **Visibility for IoT/Unmanaged Devices:** Extends visibility and security to all devices, including unmanaged IoT devices, without needing additional sensor deployments.

- **High Availability:** Supports active/active and active/passive modes for high availability deployments.

- **Centralized Management:** Enables centralized administration via the Panorama network security management platform or Strata Cloud Manager.

- **VPN support:** The PA-5400 series fully supports both IPsec and SSL VPN capabilities, including the company's own GlobalProtect large scale SSL VPN solution. Robust encryption, authentication, and key exchange support is provided for site-to-site and remote user VPN access.

In summary, the PA-5400 series provides machine learning powered inline threat prevention, high performance and capacity, comprehensive network security functionality, 5G/IoT visibility, high availability, and centralized management - tailored for large enterprises, data centers and service providers.

### 2. SolarWinds Security Event Manager (SEM)

- It integrates both the functions of IDS and IPS in Security Event Manager (SEM), will be another pair of eyes watching 24/7 for suspicious activity and responding in real time to reduce its impact. Minimize the time it takes to prepare and demonstrate compliance with audit proven reports and tools for HIPAA, PCI DSS, SOX, and more. Virtual appliance deployment, intuitive UI, and out-of-the-box content means you can start getting valuable data from your logs with minimal expertise and time.

- **Incidence Response:** Quick to analyze data logs and find patterns between them, well defined data flow. Increases response capabilities, responds to threat as soon as alarm is triggered work, Easily configure incident responses to complex threats.

- **Automated SIEM monitoring:** Improve SIEM monitoring by aggregating logs in a single location, detect security risks with real-time analysis, monitor proactively and automate remediation.

- **File Integrity Monitoring Software:** Track file and directory access, movement, and shares, use a file integrity checker to detect malware threats, demonstrate FIM security compliance requirements, easily perform Windows file integrity monitoring.

- **Compliance Reporting Software for IT:** Collect and correlate log data to help satisfy various compliance requirements, generate internal and external regulatory compliance reports, schedule reports to run automatically or run as needed.

### 3. SentinelOne Active EDR and Antivirus

- Anti Virus, EPP and EDR do not solve the cybersecurity problem for the enterprise. To compensate, some rely on additional services to close the gap. But relying on the cloud increases dwell time. Depending on connectivity is too late in the game, as it takes only seconds for malicious activity to infect an endpoint, do harm, and remove traces of itself. This dependency is what makes the EDR tools of today passive as they rely on operators and services to respond after it's already too late. The technology of TrueContext transforms the EDR to be Active, as it responds in real time, turning dwell time into no time.

- ActiveEDR empowers security teams and IT admins to focus on the alerts that matter, reducing the time and cost of bringing context to the complicated and overwhelming amount of data needed with other, passive EDR solutions.

- The introduction of ActiveEDR is similar to other technologies that helped humans to be more efficient and save time and money. Like the car replaced the horse and the autonomous vehicle will replace vehicles as we know them today, ActiveEDR is transforming the way enterprises understand endpoint security.

#### Features:
1. Combine static and behavioral detections to neutralize known and unknown threats.
2. Eliminate analyst fatigue with automated responses to suspicious behavior.
3. Proactively prevent threats by extending your endpoint visibility.
4. Build further, customized automations with one API with 350+ functions.

### 4. Acronis Device Lock DLP

A data loss prevention service offered by Acronis, a SAAS product designed to prevent unauthorized access to sensitive data in case of device loss or theft thus defending against data breaches. Having following features:

- **Device Control and Data Encryption:** Encrypt data on both removable and fixed drives to ensure the safety of sensitive information.

- **Centralized management and audit reporting:** We can control security policies for many devices and mobile devices centrally.

- **Endpoint protection integration:** Easy to integrate in SIEM.

### 5. Properly Reconfiguring IAM

- **Granting least privileges:** This means giving minimum permissions for each entity and then gradually increasing their privileges according to the need.

- **MFA:** Implementing multifactor authentication on places it is required, although this may slow down some processes but it will make it more secure.

- **Rotating credentials:** Credentials should be rotated periodically as any credential active for too long increases the risk of compromise.

### 6. Physical Security Measures

- Using access cards for authorized personnels, limiting access to important resources to the assigned individuals. Implementing biometric authentication and authorization with MFA. Setting up surveillance for the resource rooms that are monitored 24/7. Maintaining logs of people accessing these records.

### 7. Securing Locally Hosted Web Server

The website is the only thing that is accessible outside of the network, we need to sanitize and handle all the incoming and outgoing packets properly to stop or remove any suspicious activity. Following are some of the measures that can be taken to secure the web server:

1. **SSL/TLS encryption:** These two protocols provide transparent certificates for the client as well as for the server side to maintain the integrity of their HTTP transaction. They encrypt the communication, and make them unique only the client and server can understand the information being shared in the communication medium.

2. **Access Control:** Utilizing string passwords, limiting access to the server to authorized users, and putting multi-factor authentication into place.

3. **Content Security Policy:** Developers can put a limits on the content being displayed on the page and what parameters the user can interact with.

4. **Web application Firewall:** cloudflare firewall is well documented and applied widely and is the most reliable WAF, it maintains logs, admins can easily apply ACLs, and is very effective in analyzing and alerting about malicious packet behaviour.

### 8. Teaching Security Practices to the Employees

The weakest link in a security infrastructure is a human, they are the most susceptible to getting exploited and easily manipulated to do others biding. Following are some security measures you can implement to educate them on it:

- **Education and testing:** Employees should be trained on how to handle external emails and abnormal emails, what information can be disclosed and what information should not be disclosed during a conversation with anyone in organization and outside of organization. After educating them, they should also perform an assessment on a periodic basis to understand what more improvements can be done to the training and how the employees can be stopped from being exploited.

- **Policies and procedures:** It is important to educate the employees on the companies policies and procedures. This includes reporting incidents to IT and adhering to the organization's incident response policies.

### 9. Disaster Management and Data Recovery Plans

#### Data Backup Plan:
1. Establish procedures for regular and secure backups of PHI and other critical data, both electronic and paper-based.
2. Implement off-site storage of backup data in a secure location, preferably at a geographically separate site.
3. Ensure that backup data is encrypted and access is restricted to authorized personnel.

#### Disaster Recovery Plan:
1. Define roles and responsibilities for disaster response and recovery teams.
2. Outline procedures for restoring data and systems from backups in the event of a disaster.
3. Identify alternate sites or locations for operations if the primary site is unavailable.
4. Establish procedures for maintaining business continuity and minimizing disruptions to critical services.

#### Emergency Mode Operation Plan:
1. Develop procedures for operating in emergency mode if systems or facilities are compromised.
2. Define methods for maintaining access to PHI and essential operations during an emergency.
3. Establish protocols for secure communication and coordination among personnel during an emergency.

#### Testing and Maintenance:
1. Regularly test and update the disaster management and data recovery plan to ensure its effectiveness and accuracy.
2. Conduct simulations or drills to evaluate the plan and identify areas for improvement.
3. Maintain up-to-date documentation and training materials for all relevant personnel.

#### Contingency Planning:
1. Identify alternative methods for providing critical services if primary systems or facilities are unavailable.
2. Establish agreements or contracts with third-party vendors or service providers for emergency support if needed.

#### Incident Response and Reporting:
1. Develop procedures for detecting, reporting, and responding to security incidents or data breaches.
2. Outline the process for notifying appropriate authorities, such as the Department of Health and Human Services (HHS), in the event of a breach involving PHI.

#### Workforce Training:
1. Provide regular training to all workforce members on the disaster management and data recovery plan, their roles and responsibilities, and the importance of adhering to HIPAA guidelines.

---

## 12. Zero Trust Security Model for Healthcare Infrastructure

### 1. HIPAA Compliance:

- **Access Control:** Zero Trust enforces granular access controls throughout the healthcare infrastructure, ensuring that only authorized personnel can access sensitive patient data stored in the Linux network. This includes implementing role-based access control (RBAC) and multifactor authentication (MFA) mechanisms.

- **Encryption:** All data, including electronic protected health information (ePHI), is encrypted both at rest and in transit within the network. This encryption extends to communication channels between the web server in the DMZ and backend servers to safeguard patient privacy and confidentiality.

- **Continuous Monitoring:** The Zero Trust model incorporates real-time monitoring of network traffic and user activities, enabling the detection of anomalous behavior or potential security threats. This proactive approach aligns with HIPAA's requirement for continuous security monitoring and incident response.

### 2. GDPR Compliance:

- **Data Protection:** Zero Trust employs robust encryption techniques to protect personal data stored within the healthcare infrastructure, such as patient medical records and research data. Additionally, access controls are strictly enforced to ensure that only authorized personnel can access and process personal data.

- **Accountability and Governance:** Identity and access management (IAM) solutions are implemented to maintain accountability by tracking user access and activities across the network. Detailed audit logs provide visibility into data handling practices, supporting compliance with GDPR's accountability and governance requirements.

- **Data Breach Notification:** Zero Trust's continuous monitoring capabilities enable rapid detection and response to data breaches, ensuring compliance with GDPR's data breach notification obligations. Incident response procedures are in place to promptly investigate and mitigate any security incidents that may occur.

### 3. SOC 2 Compliance:

- **Security and Availability:** The Zero Trust model enhances security and availability by implementing network segmentation to isolate critical systems and protect customer data. This includes securing the web server in the DMZ and backend servers within the Windows and Linux networks to prevent unauthorized access.

- **Monitoring and Incident Response:** Real-time monitoring tools are deployed to monitor network traffic, detect security incidents, and respond promptly to any threats or vulnerabilities. Incident response plans are documented and tested regularly to ensure readiness in the event of a security breach.

- **Trust Services Criteria:** Zero Trust aligns with SOC 2's Trust Services Criteria by addressing key principles such as security, availability, processing integrity, confidentiality, and privacy. By adopting a comprehensive approach to security and compliance, the healthcare infrastructure can demonstrate adherence to SOC 2 requirements.

In summary, the Zero Trust Security Model provides a robust framework for securing the healthcare infrastructure described in the scenario while ensuring compliance with HIPAA, GDPR, and SOC 2 regulations. By implementing strict access controls, encryption measures, continuous monitoring, and incident response capabilities, the organization can protect sensitive patient data, maintain operational resilience, and mitigate the risk of security breaches.

---

## 13. Improved Infrastructure

*[Architecture diagram would be included here in the original document]*

---

## 14. Cost Estimation

### Annual Subscription Costs
- SentinelOne AV: $3,600
- SentinelOne XDR: $7,200
- SolarWinds SEM: $3,510
- Acronis Device Lock DLP: $3,510
- Web Application Firewall (WAF): $3,000
- IAM implementation: $18,000
- Security Engineer consultation: $100,000
- Training and Awareness: $50,000
- Compliance risk assessment: $37,000
- Email Security Subscription: $15,000

### One-time Purchase Costs:
- Palo Alto Networks PA-5400 Series NGFWs: $70,000
- Physical Security: $30,000
- Overall Risk Assessment: $20,000
- Disaster Recovery Assessment: $20,000
- VAPT: $38,000

### Total Cost
- **Total Annual Subscriptions Cost:** $240,320
- **Total One-time Cost:** $178,000
- **Total Cost (Annual + One-time):** $418,320
- **Budget Left:** $81,680

The residual budget presents an opportunity to augment our security infrastructure by enlisting the expertise of a junior security analyst. This addition would fortify our defense strategy by enhancing our capacity for threat detection, incident response, and security operations. Leveraging this allocation, we can bolster our team's capabilities in proactively identifying and mitigating potential vulnerabilities, conducting comprehensive security assessments, and reinforcing our adherence to regulatory compliance standards. The inclusion of a junior security analyst underscores our commitment to maintaining a robust security posture and fortifying our organizational resilience against evolving cyber threats.

---

## 15. References

1. https://www.logicworks.com/blog/2015/05/aws-iam-security-cloud-hipaa-compliance/
2. https://public3.pagefreezer.com/browse/HHS.gov/20-06-2023T05:11/https://www.hhs.gov/sites/default/files/nist-csf-to-hipaa-security-rule-crosswalk-02-22-2016-final.pdf
3. https://www.solarwinds.com/kiwi-syslog-server/integrations/security-event-manager
4. https://www.acronis.com/en-us/products/cloud/cyber-protect/data-loss-prevention/
5. https://www.sentinelone.com/platform/
6. https://www.paloaltonetworks.com/resources/datasheets/pa-5400-series
7. https://www.cloudflare.com/learning/security/glossary/what-is-zero-trust/
8. https://www.checkpoint.com/cyber-hub/cyber-security/what-is-soc-2-compliance/
9. https://gdpr-info.eu/
10. https://learn.microsoft.com/en-us/azure/security/develop/threat-modeling-tool-threats
11. https://aws.amazon.com/iam/
