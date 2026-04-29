import sys

file_path = r'd:\ADUY\252\An_Ninh_Mang\CO3069_252_CLM\main_fix.tex'
with open(file_path, 'r', encoding='utf-8') as f:
    lines = f.readlines()

new_content = r"""%============================================================
%  CHAPTER 3 -- SYSTEM ANALYSIS AND DESIGN
%============================================================
\chapter{System Analysis and Design}
\label{chap:analysis_design}

\section{Topic Analysis}

The assignment mandates the design and implementation of a Centralized Log Management (CLM) system. The core objectives to be fulfilled are:
\begin{enumerate}[leftmargin=1.5em]
    \item \textbf{Research Centralized Log Management}: Understand the theoretical foundations, architecture, and security requirements of CLM systems.
    \item \textbf{Select and Deploy an Open-Source CLM}: Evaluate available solutions and deploy a fully functional system based on open-source technologies.
    \item \textbf{Test and Evaluate}: Conduct rigorous functional and security testing to validate the deployment against real-world attack scenarios.
\end{enumerate}

\subsection{Solution Selection}
To fulfill the second objective, the \textbf{ELK Stack} (Elasticsearch 8.x, Logstash, Kibana) combined with Filebeat was selected over alternatives like Graylog or OpenSearch. The ELK Stack provides industry-standard capabilities, rich pre-built modules for security events (Nginx, SSH), and robust built-in security features (TLS, RBAC) out-of-the-box in version 8.x.

\section{System Architecture Design}

The system is designed as a containerized architecture using Docker Compose to ensure portability and reproducibility. 

\subsection{Container Topology}
The topology consists of four interconnected services on a dedicated Docker bridge network (\texttt{elk}):
\begin{itemize}[leftmargin=1.5em]
    \item \textbf{Elasticsearch}: Configured as a single-node cluster for storage, with X-Pack security enabled for TLS transport and HTTP.
    \item \textbf{Logstash}: Acts as the centralized processor, mounting pipeline configurations and receiving logs from Filebeat.
    \item \textbf{Kibana}: Serves as the web interface for visualization and alerting, connecting securely to Elasticsearch.
    \item \textbf{Filebeat}: The log shipper, mounted with host log directories (\texttt{/var/log}) to collect system and web server logs.
\end{itemize}

\section{Security Architecture Design}

\subsection{Threat Model for the CLM System}
A CLM system is a high-value target. Compromising it could allow an attacker to erase log evidence or cause a denial-of-service. Applying the STRIDE model, key threats include:
\begin{itemize}[leftmargin=1.5em]
    \item \textbf{Spoofing / Tampering}: Rogue shippers injecting false logs, or insiders modifying indexed logs.
    \item \textbf{Information Disclosure}: Unauthenticated access to sensitive log data in transit or at rest.
\end{itemize}

\subsection{Cryptographic Design (TLS and HMAC)}
To mitigate these threats, the design incorporates two primary cryptographic controls:

\textbf{1. TLS 1.3 for Data in Transit}: All inter-component communication (Filebeat to Logstash, Logstash to Elasticsearch, Kibana to Elasticsearch) is encrypted using TLS. Certificates are generated centrally using the \texttt{elasticsearch-certutil} tool, which acts as the Certificate Authority (CA) for the stack.

\textbf{2. HMAC-SHA256 for Log Integrity}: To prevent tampering, a cryptographic signature is generated for every log event. The payload for the HMAC is designed by concatenating canonical fields:
\begin{equation}
    Payload = Timestamp | Hostname | Source\_IP | Username | Message
\end{equation}
By signing these specific fields, any unauthorized modification to the log's content or metadata will result in a mismatched hash during verification.

\subsection{Role-Based Access Control (RBAC)}
The principle of least privilege is enforced using Elasticsearch's RBAC. Roles are divided strictly: \texttt{shipper} (write-only for Logstash), \texttt{log\_viewer} (read-only), and \texttt{admin} (full access).

%============================================================
%  CHAPTER 4 -- IMPLEMENTATION AND EVALUATION
%============================================================
\chapter{Implementation and Evaluation}
\label{chap:impl_eval}

\section{System Implementation}

\subsection{TLS Configuration}
All inter-component communication uses TLS 1.3, enforced via \texttt{ssl\_supported\_protocols: ["TLSv1.3"]} in the Elasticsearch configuration. Cipher suites are restricted to forward-secret AEAD modes.

\subsection{Logstash Pipeline and HMAC Implementation}
The core logic resides in Logstash. A Ruby filter calculates the HMAC-SHA256 signature using a secret key (\texttt{LOG\_HMAC\_KEY}) injected via environment variables.

\begin{lstlisting}[language=ruby, caption={Logstash HMAC integrity filter}]
filter {
  ruby {
    code => '
      require "openssl"
      secret_key = ENV["LOG_HMAC_KEY"] || "default-insecure-key"
      timestamp = event.get("@timestamp").to_s rescue ""
      hostname  = event.get("[host][name]").to_s rescue ""
      source_ip = event.get("[source][ip]") || event.get("source_ip") || ""
      username  = event.get("[user][name]") || event.get("username") || ""
      message   = event.get("message").to_s rescue ""
      payload   = "#{timestamp}|#{hostname}|#{source_ip}|#{username}|#{message}"
      hmac      = OpenSSL::HMAC.hexdigest("SHA256", secret_key, payload)
      event.set("[integrity][hmac]", hmac)
    '
  }
}
\end{lstlisting}

\subsection{Detection Use Cases Implemented}
Logstash utilizes Grok filters to parse raw logs and apply specific tags for Kibana alerts:
\begin{itemize}[leftmargin=1.5em]
    \item \textbf{Failed SSH Logins}: Parses \texttt{auth.log} for "Failed password", adding the \texttt{ssh\_failed\_login} tag.
    \item \textbf{Web Application Attacks}: Inspects Nginx access logs using regex for SQL injection payloads (e.g., \texttt{UNION SELECT}) and XSS payloads (e.g., \texttt{<script>}), applying the \texttt{security\_alert} tag.
\end{itemize}

\section{Testing and Evaluation}

\subsection{Security Testing Simulation}
A shell script (\texttt{generate\_test\_logs.sh}) was developed to simulate attacks by injecting crafted logs into the monitored files.
\begin{itemize}[leftmargin=1.5em]
    \item \textbf{SSH Brute-Force}: Injected multiple SSH failure logs. The pipeline successfully parsed the source IP and generated a critical Kibana alert.
    \item \textbf{SQL Injection and XSS}: Injected Nginx logs containing malicious HTTP GET requests. The Logstash regex patterns successfully flagged these as \texttt{web\_attack}.
\end{itemize}

\subsection{Integrity Verification Evaluation}
A Python verification script (\texttt{verify\_log\_integrity.py}) was built to query Elasticsearch and validate the HMAC.
\begin{itemize}[leftmargin=1.5em]
    \item \textbf{Valid Document}: The script recalculates the HMAC using the same payload logic. The output matched the stored hash: \texttt{SUCCESS: Integrity Verified!}.
    \item \textbf{Tampered Document}: The \texttt{message} field of a log entry was manually altered via the API. The script immediately detected the hash mismatch: \texttt{FAILURE: Integrity Check Failed!}.
\end{itemize}

\subsection{Performance Evaluation}
\begin{table}[H]
\centering
\caption{Peak Resource Utilization (Single-Node)}
\label{tab:resources}
\begin{tabular}{lrr}
\toprule
\textbf{Container} & \textbf{CPU (cores)} & \textbf{Memory (GB)} \\
\midrule
Elasticsearch & 2.1 & 2.8 \\
Logstash      & 1.4 & 1.2 \\
Kibana        & 0.3 & 0.6 \\
Filebeat      & 0.1 & 0.1 \\
\textbf{Total}& \textbf{3.9} & \textbf{4.7} \\
\bottomrule
\end{tabular}
\end{table}

The system handles ingestion efficiently, though the Ruby HMAC calculation in Logstash introduces a minor CPU overhead. The peak memory footprint of 4.7 GB is acceptable for a monolithic deployment.

%============================================================
%  CHAPTER 5 -- CONCLUSION
%============================================================
\chapter{Conclusion}
\label{chap:conclusion}

\section{Key Findings}

This assignment demonstrated that a Centralized Log Management system built on the open-source ELK Stack provides a viable and feature-complete security monitoring platform. The implemented solution directly satisfies the assignment objectives:
\begin{enumerate}[leftmargin=1.5em]
    \item \textbf{Effective threat detection}: All modelled attack scenarios (SSH brute force, SQLi/XSS) were detected and properly tagged.
    \item \textbf{Cryptographic integrity}: HMAC-SHA256 signing provides strong tamper evidence, ensuring the reliability of the collected logs.
    \item \textbf{Secure transmission}: Mandatory TLS 1.3 authentication prevents both eavesdropping and rogue log injection.
\end{enumerate}

\section{Lessons Learned}
\begin{itemize}[leftmargin=1.5em]
    \item Security should be enabled \textit{from day one}: Retrofitting TLS onto an already-running cluster is significantly more disruptive than enabling it at bootstrap.
    \item Log quality matters: Unstructured logs require complex Grok parsing, which consumes CPU resources. Transitioning to structured JSON logs at the source is highly recommended.
\end{itemize}

\section{Future Directions}
\begin{itemize}[leftmargin=1.5em]
    \item Migrate to a \textbf{three-node Elasticsearch cluster} for high availability and fault tolerance.
    \item Implement \textbf{Index Lifecycle Management (ILM)} to automate the deletion of old logs and prevent disk exhaustion.
    \item Integrate \textbf{Auditbeat} to monitor changes to critical system files alongside standard application logs.
\end{itemize}
"""

if not new_content.endswith("\n"):
    new_content += "\n"

new_lines = lines[:527] + [new_content] + lines[1087:]
with open(file_path, 'w', encoding='utf-8') as f:
    f.writelines(new_lines)

print("Update successful!")
