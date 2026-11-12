Security Header Inconsistency Within Websites: New Measurements and Comparison with Prior Work

**Group Members:** Mirza Zuhayr, Muhammad Shayan Waqar, Ishaq Breiwish

**Motivation** 

Our project will study whether or not websites consistently deliver Content Security Policy (CSP) and HTTP Strict Transport Security (HSTS) headers across their public pages. 

Checking only the homepage may not provide a complete picture of its security-header deployment, since headers may be configured differently / missing on other pages. To address this, we will compare the headers returned by each website’s homepage with those returned by other sampled public ages on the same website, to measure how often there are discrepancies. Our goal is to determine how representative homepage-only measurements are of security-header deployment across sampled pages, while distinguishing differences in header delivery from evidence of actual security vulnerabilities.

**Prior Work:**   
Prior research, including *Reining in the Web’s Inconsistencies with Site Policy*, has examined how security policies vary across pages within a website. We will use this work as a starting point, then collect current measurements of CSP and HSTS headers across homepages and other public pages. Our project is an updated measurement and comparison rather than a claim that these inconsistencies have not been studied before. We’ll compare our sampling and methods with the prior work and discuss any limits to comparing the results directly.

**Approach \- Measurement Project:** 

Our approach first includes selecting 50–100 websites from a Tranco or Cloudflare Radar (or a combination of both). For collection, we plan to build a Python crawler that will visit each homepage and up to five linked pages on the same origin in order to collect data such as URLs, timestamps, HTTP status codes, redirect destinations, and Content Security Policy (CSP) and HTTP Strict Transport Security (HSTS) headers. For analysis or metrics, we can quantify header adoption, differences across pages, and see how often homepage-only checks miss the page differences. Once we repeat our collection once more and validate the data, we can compare our work with prior research and data while factoring in the differences between our methods and the prior research methods to draw conclusions on the changes. Some limitations for this project could be sample size, crawl depth, and the exclusion of authenticated pages. In addition, our requests will most likely be limited to only public pages that don’t have authentication. Our main deliverables will be the Python collector, CSV dataset, and analysis script producing summary tables.

