<h1> Log analysis: Exposed RDP with weak password </h1>

*Project in Network Security lecture.*  
*Reference [NS_final_project.md](https://github.com/hy-qqqqq/rdp_log_analysis/blob/main/NS_final_project.md) for detailed explanation.*

<h2> RDP exposed </h2>

<h3> Vulnerabilities </h3>

* weak credentials
  * the attacker may try to brute-force the weak credentials and gain access to the victim machine. As a result, we might see some failed to login messages in the logs.
* unrestricted port access
  * some known ports, such as RDP (3389), SMB (445), mDNS (5353)
  * the attacker may do port scanning to find the open ports.

<h3> Techniques used in this scenario </h3>

* Port-scanning
* RDP brute-forcing
* Ransomware execution

<h2> Content </h2>

* IoC and the method to discover this attack
* Timestamps of each technique used
* Detection method

<h2> Others </h2>

<h3> ELK </h3>

* ElasticSearch (9200 port) `database`
* Logstash (5044 port) `filter`
* Kibana (5601 port) `visualization tool`

<h3> Beats </h3>

* winlogbeat with sysmon: security or any application messages
* zeek: network traffic
