from synack import synack
from datetime import datetime
from dateutil.relativedelta import relativedelta
from os import path
import csv
import os

s = synack()
s.connectToPlatform()
s.getSessionToken()

vulns = s.getVulns("accepted")

vulns_data = []
count = 0
today = datetime.now()
past = datetime.today() + relativedelta(months=-3)
total_cvss = 0

# legends calculations
cvss_9_or_above = 0
unique_targets = {}
# unique orgs we can't really calculate because the org field is not available on the vuln

for v in vulns:
    if count % 50 == 0:
        print("Analyzing %d of %d" % (count, len(vulns)))
    count = count + 1

    expanded_vuln = s.getVuln(v['id'])
    
    if float(expanded_vuln['cvss_final'] ) >= 9.0:
        cvss_9_or_above = cvss_9_or_above + 1
    
    unique_targets[v['listing']['codename']] = True

    vulns_data.append({
        "id": v['id'],
        "title": v['title'],
        # not sure what to do with timestamp format :)
        "created_at": expanded_vuln['created_at'],
        "resolved_at": expanded_vuln['resolved_at'],
        "amount": v['market_value_final'],
        "subcategory": v['category'],
        "category": v['category_parent'],
        "target": v['listing']['codename'],
        "cvss": expanded_vuln['cvss_final'],
        "quality": expanded_vuln['quality_score']
    })

    d = datetime.fromtimestamp(expanded_vuln['created_at'])
    if (d > past):
        total_cvss += expanded_vuln['cvss_final']

# for Proven SRT cohort
print("Total CVSS within the past 3 months: %.2f (%s - %s)" %(total_cvss,past.date().strftime("%x"),today.date().strftime("%x")))
# for Legends approximation
print("Legends Unique Targets: %d/250 Vulns: %d/1500 Vulns > 9.0: %d/250" % (len(unique_targets.keys()), len(vulns), cvss_9_or_above))


columns = ["id", "created_at", "title", "amount", "category", "subcategory", "target", "cvss", "quality", "created_at", "resolved_at"]
now = datetime.now()
filename = "synstats-%s-%s-%s.csv"%(str(now.year),str(now.month),str(now.day))
with open(filename,"w") as f:
    writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(vulns_data)
