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
for v in vulns:
    if count % 50 == 0:
        print("Analyzing %d of %d" % (count, len(vulns)))
    count = count + 1

    expanded_vuln = s.getVuln(v['id'])
    
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

print("Total cvss within the past 3 months: %.2f (%s - %s)" %(total_cvss,past.date().strftime("%d-%m-%Y"),today.date().strftime("%d-%m-%Y")))
columns = ["id", "created_at", "title", "amount", "category", "subcategory", "target", "cvss", "quality", "created_at", "resolved_at"]
now = datetime.now()
filename = "synstats-%s-%s-%s.csv"%(str(now.year),str(now.month),str(now.day))
with open(filename,"w") as f:
    writer = csv.DictWriter(f, fieldnames=columns, extrasaction="ignore", lineterminator="\n")
    writer.writeheader()
    writer.writerows(vulns_data)
