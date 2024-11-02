# Censorship Detector 

This tool allows to identify when a specific DNS resolver censors some domains by means of DNS response manipulation. This kind of censorship is typically employed by redirecting users to a blockpage as soon as they are trying to reach a website hidden by the authority owning the resolver.

The tool is based on a "test vs. control" philosophy, so its workflow is split into two phases: the first one consists of creating a trusted list of resolutions using a legit DNS resolver, such as Google (8.8.8.8) or Cloudflare (1.1.1.1), while in the second one the actual analysis of the responses provided by the suspicious resolver is performed.

This work is inspired by [CERTainty](https://censoredplanet.org/certainty), a tool used for detecting and measuring censorship on the internet, developed and described in an [article](https://arxiv.org/abs/2305.08189) by Elisa Tsai, Deepak Kumar, Ram Sundara Raman, Gavin Li, Yael Eiger and Roya Ensafi.

## Tool Execution

To execute the tool in the correct way:

* Set the machine's DNS resolver to a trusted one (this can be done on Linux by modifying the `/etc/resolv.conf` file, removing or commenting the nameserver currently in use, and adding the desired one, e.g., `nameserver 8.8.8.8`). 

* Run `control_resolutions.py`.

* Set the machine's DNS resolver to the suspicious one to be analyzed (in the same manner described before).

* Run `censorship_detector.py`.

## Schema

* `input.csv` contains a list of the most visited domains on the internet, extrapolated by the [Tranco top 1 Million list](https://tranco-list.eu/).

* `output_good.csv` contains the list of trusted resolutions generated using the trusted DNS resolver.

* `output_bad.csv` contains the list of untrusted resolutions generated using the DNS resolver under analysis.

* `mismatched_resolutions.csv` contains the list of mismatched resolutions obtained by comparing the trusted and the untrusted ones.

* `mozilla_trusted_ca_certificates.crt` contains a [list of trusted CA certificates](https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReport) provided by Mozilla.

* `certificates.csv` is generated after analyzing the certificates of the domains with suspicious (mismatched) resolutions, and it contains some information about their certificates, such as their validity, the eventual mismatch between the domain name and the name on the certificate, and the subject of the certificate itself.

* `/certificates` is a directory filled with the certificates retrieved when contacting the domains that showed mismatched resolutions; each file contains two versions of the certificate: the original one and the readable one.

* `blockpage_typical_words.csv` contains a list of words commonly found in blockpages, paired with a score; this list was generated by performing a word count on a [list of blocking fingerprints](https://github.com/ooni/blocking-fingerprints?tab=readme-ov-file#blocking-fingerprints) that includes data from OONI, Censored Planet and Citizen Lab.

* `webpages.csv` is generated after trying to establish an HTTP connection with the websites that displayed suspicious certificates (invalid or with mismatched names); it contains the HTTP status code returned by the website, along with a score that indicates how likely it is for the obtained page to be a blockpage.

* `/webpages` is a directory filled with the HTMLs of the retrieved webpages, with the purpose of visually verifying whether a specific domain was actually hidden by means of a blockpage or not.

![diagram](/img/diagram_nobg.png)
